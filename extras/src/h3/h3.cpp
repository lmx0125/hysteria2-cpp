#include "hy2/h3/h3.hpp"

#include <stdexcept>
#include <cstdio>
#include <cstdlib>

namespace hy2::h3 {

// HTTP/3 requires lowercase field names (RFC 9110 §5.1); quic-go rejects
// anything else with H3_FIELD_INVALID.
static std::string LowerName(const std::string& n) {
    std::string r;
    r.reserve(n.size());
    for (char ch : n) {
        r.push_back(ch >= 'A' && ch <= 'Z'
                        ? static_cast<char>(ch - 'A' + 'a')
                        : ch);
    }
    return r;
}

// ---------------------------------------------------------------------------
// Varint
void WriteVarint(std::vector<uint8_t>& out, uint64_t v) {
    if (v < 0x40) {
        out.push_back(static_cast<uint8_t>(v));
    } else if (v < 0x4000) {
        out.push_back(static_cast<uint8_t>(0x40 | (v >> 8)));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    } else if (v < 0x40000000) {
        out.push_back(static_cast<uint8_t>(0x80 | (v >> 24)));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>(v >> 8) & 0xFF);
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    } else {
        out.push_back(static_cast<uint8_t>(0xC0 | (v >> 56)));
        for (int i = 5; i >= 0; --i) {
            out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
        }
    }
}

static uint64_t ReadVarintStream(IQuicStream& s) {
    uint8_t first = 0;
    size_t n = s.Read(&first, 1);
    if (n == 0) throw std::runtime_error("h3: eof in varint");
    static const uint8_t kLen[4] = {1, 2, 4, 8};
    static const uint8_t kMask[4] = {0x3F, 0x3F, 0x0F, 0x03};
    int idx = (first >> 6) & 0x3;
    int total = kLen[idx];
    uint64_t value = first & kMask[idx];
    for (int i = 1; i < total; ++i) {
        uint8_t b = 0;
        size_t got = s.Read(&b, 1);
        if (got == 0) throw std::runtime_error("h3: eof in varint body");
        value = (value << 8) | b;
    }
    return value;
}

std::vector<uint8_t> EncodeFrameHeader(uint64_t type, size_t payloadLen) {
    std::vector<uint8_t> out;
    WriteVarint(out, type);
    WriteVarint(out, payloadLen);
    return out;
}

FrameHeader ReadFrame(IQuicStream& s) {
    FrameHeader f;
    f.type = ReadVarintStream(s);
    uint64_t len = ReadVarintStream(s);
    if (len > (64u << 20)) throw std::runtime_error("h3: frame too large");
    f.payload.resize(static_cast<size_t>(len));
    size_t got = 0;
    while (got < f.payload.size()) {
        size_t n = s.Read(f.payload.data() + got, f.payload.size() - got);
        if (n == 0) throw std::runtime_error("h3: eof in frame payload");
        got += n;
    }
    return f;
}

std::vector<uint8_t> BuildClientSettingsBody() {
    std::vector<uint8_t> body;
    auto add = [&body](uint64_t id, uint64_t val) {
        WriteVarint(body, id);
        WriteVarint(body, val);
    };
    add(SettingQpackMaxTableCapacity, 0);
    add(SettingQpackBlockedStreams, 0);
    add(SettingMaxFieldSectionSize, 65536);
    return body;
}

std::vector<uint8_t> BuildServerSettingsBody() {
    return BuildClientSettingsBody();
}

static void SendSettingsOnControl(IQuicConnection& conn,
                                  const std::vector<uint8_t>& settingsBody) {
    auto ctrl = conn.OpenUniStream();
    if (!ctrl) throw std::runtime_error("h3: open control stream failed");
    std::vector<uint8_t> buf;
    WriteVarint(buf, StreamTypeControl);
    auto fh = EncodeFrameHeader(FrameSettings, settingsBody.size());
    buf.insert(buf.end(), fh.begin(), fh.end());
    buf.insert(buf.end(), settingsBody.begin(), settingsBody.end());
    ctrl->Write(buf.data(), buf.size());
    // NOTE: never Close() the control stream - RFC 9114 搂7.2.4 makes that
    // an H3_CLOSED_CRITICAL_STREAM connection error (quic-go enforces it).
}

void SendControlStream(IQuicConnection& conn,
                       const std::vector<uint8_t>& settingsBody) {
    SendSettingsOnControl(conn, settingsBody);
}

// ---------------------------------------------------------------------------
// Client request
Response Request(IQuicConnection& conn,
                 const std::string& method,
                 const std::string& schemeAndHost,
                 const std::string& path,
                 const std::vector<Header>& extraHeaders,
                 const std::vector<uint8_t>* body) {
    SendControlStream(conn, BuildClientSettingsBody());

    auto stream = conn.OpenStream();

    // Pseudo headers first, per RFC 9114 搂4.3.
    std::vector<Header> headers;
    headers.emplace_back(":method", method);
    headers.emplace_back(":scheme", "https");
    headers.emplace_back(":authority", schemeAndHost);
    headers.emplace_back(":path", path);
    for (auto& h : extraHeaders) {
        if (!h.first.empty() && h.first[0] != ':') {
            headers.emplace_back(LowerName(h.first), h.second);
        } else {
            headers.push_back(h);
        }
    }

    auto encoded = QpackEncode(headers);
    auto fh = EncodeFrameHeader(FrameHeaders, encoded.size());
    std::vector<uint8_t> buf(fh.begin(), fh.end());
    buf.insert(buf.end(), encoded.begin(), encoded.end());

    if (body && !body->empty()) {
        auto dfh = EncodeFrameHeader(FrameData, body->size());
        buf.insert(buf.end(), dfh.begin(), dfh.end());
        buf.insert(buf.end(), body->begin(), body->end());
    }
    stream->Write(buf.data(), buf.size());
    stream->Close(); // end request

    // Read response frames until stream FIN.
    Response resp;
    bool gotHeaders = false;
    for (;;) {
        FrameHeader f = ReadFrame(*stream); // throws on EOF-before-headers
        if (f.type == FrameHeaders) {
            auto hs = QpackDecode(f.payload.data(), f.payload.size());
            for (auto& h : hs) {
                if (h.first == ":status") {
                    resp.StatusCode = std::atoi(h.second.c_str());
                }
            }
            resp.Headers = std::move(hs);
            gotHeaders = true;
        } else if (f.type == FrameData) {
            resp.Body.insert(resp.Body.end(), f.payload.begin(), f.payload.end());
        } else {
            // Unknown/unsupported frame types MUST be ignored (搂7.2.3).
            continue;
        }
        if (gotHeaders) break; // response complete on our minimal path
    }

    // Drain until EOF so the server's FIN is observed cleanly.
    try {
        uint8_t sink[512];
        while (stream->Read(sink, sizeof(sink)) > 0) {}
    } catch (...) {}

    return resp;
}

// ---------------------------------------------------------------------------
// Server side
ServerRequest ReadRequest(IQuicStream& s) {
    ServerRequest req;
    bool gotHeaders = false;

    for (;;) {
        FrameHeader f = ReadFrame(s);
        if (f.type == FrameHeaders) {
            if (std::getenv("HY2_QUIC_DEBUG")) {
                std::fprintf(stderr, "[h3] req HEADERS %zu bytes:",
                             f.payload.size());
                for (size_t i = 0; i < f.payload.size() && i < 48; ++i)
                    std::fprintf(stderr, " %02x", f.payload[i]);
                std::fprintf(stderr, "\n");
            }
            auto hs = QpackDecode(f.payload.data(), f.payload.size());
            for (auto& h : hs) {
                if (h.first == ":method") req.Method = h.second;
                else if (h.first == ":scheme") req.Scheme = h.second;
                else if (h.first == ":authority") req.Authority = h.second;
                else if (h.first == ":path") req.Path = h.second;
                else req.Headers.emplace_back(h.first, h.second);
            }
            gotHeaders = true;
        } else if (f.type == FrameData) {
            req.Body.insert(req.Body.end(), f.payload.begin(), f.payload.end());
        } else {
            continue;
        }
        if (gotHeaders) break;
    }

    // Drain remaining DATA until FIN (auth requests have no body, but be
    // liberal). A non-blocking style bounded drain:
    try {
        uint8_t sink[512];
        // The stream ends after HEADERS for hysteria auth; a single extra
        // read attempt returning 0 means peer FIN already seen.
        size_t n = s.Read(sink, sizeof(sink));
        (void)n;
    } catch (...) {
    }
    return req;
}

void SendResponse(IQuicStream& s, int status,
                  const std::vector<Header>& headers,
                  const std::vector<uint8_t>* body) {
    std::vector<Header> hs;
    hs.emplace_back(":status", std::to_string(status));
    for (auto& h : headers) {
        if (!h.first.empty() && h.first[0] != ':') {
            hs.emplace_back(LowerName(h.first), h.second);
        } else {
            hs.push_back(h);
        }
    }

    auto encoded = QpackEncode(hs);
    auto fh = EncodeFrameHeader(FrameHeaders, encoded.size());
    std::vector<uint8_t> buf(fh.begin(), fh.end());
    buf.insert(buf.end(), encoded.begin(), encoded.end());

    if (body && !body->empty()) {
        auto dfh = EncodeFrameHeader(FrameData, body->size());
        buf.insert(buf.end(), dfh.begin(), dfh.end());
        buf.insert(buf.end(), body->begin(), body->end());
    }
    s.Write(buf.data(), buf.size());
    s.Close();
}

} // namespace hy2::h3

