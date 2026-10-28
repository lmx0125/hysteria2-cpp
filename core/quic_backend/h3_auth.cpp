// h3_auth.cpp - HTTP/3 auth round-tripper for the real QUIC backend.
// Sends POST /auth via H3, parses the response properly.
// Matches the Go code's http3.RoundTripper auth flow.
#include "hy2/quic_backend/h3_auth.hpp"

#include <cstring>
#include <stdexcept>
#include <vector>

#include "hy2/h3/h3.hpp"
#include "hy2/h3/qpack.hpp"
#include "hy2/protocol.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

namespace hy2::quic_backend {

namespace {

// ---------------------------------------------------------------------------
// QUIC varint encoding (RFC 9000 16)
void WriteVarint(std::vector<uint8_t>& out, uint64_t v) {
    if (v < 0x40) {
        out.push_back(static_cast<uint8_t>(v));
    } else if (v < 0x4000) {
        out.push_back(static_cast<uint8_t>(0x40 | (v >> 8)));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    } else if (v < 0x40000000) {
        out.push_back(static_cast<uint8_t>(0x80 | (v >> 24)));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    } else {
        out.push_back(static_cast<uint8_t>(0xC0 | (v >> 56)));
        for (int i = 5; i >= 0; --i) {
            out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
        }
    }
}

uint64_t ReadVarint(const uint8_t*& p, const uint8_t* end) {
    if (p >= end) throw std::runtime_error("h3_auth: truncated varint");
    uint8_t first = *p++;
    int len = 1;
    uint64_t value = first & 0x3F;
    int shift = 0;
    switch (first >> 6) {
    case 0: return value;
    case 1: len = 2; shift = 8; break;
    case 2: len = 4; shift = 24; break;
    case 3: len = 8; shift = 56; break;
    }
    for (int i = 1; i < len; ++i) {
        if (p >= end) throw std::runtime_error("h3_auth: truncated varint body");
        value = (value << 8) | *p++;
    }
    return value;
}

// ---------------------------------------------------------------------------
// H3 frame helpers
constexpr uint64_t kFrameHeaders = 0x01;
constexpr uint64_t kFrameData = 0x00;
constexpr uint64_t kFrameSettings = 0x04;
constexpr uint64_t kStreamTypeControl = 0x00;

// H3 settings IDs
constexpr uint64_t kSettingQpackMaxTableCapacity = 0x01;
constexpr uint64_t kSettingQpackBlockedStreams = 0x07;
constexpr uint64_t kSettingMaxFieldSectionSize = 0x06;

// ---------------------------------------------------------------------------
// Minimal QPACK encoder (static-table-only, matches Go's qpack)
//
// Static table indices (RFC 9204 Appendix A):
//   0: :authority ""
//   1: :path "/"
//  20: :method POST
//  23: :scheme https
//  25: :status 200
//  80: authorization ""

// Encode a QPACK header with static name reference
static void EncodeStaticNameRef(std::vector<uint8_t>& out, int nameIdx,
                                const std::string& value) {
    // Literal with static name reference: 0100xxxx (4-bit prefix, name index)
    // Then 7-bit prefix string for value
    if (nameIdx < 15) {
        out.push_back(static_cast<uint8_t>(0x40 | nameIdx));
    } else {
        // nameIdx >= 15 needs multi-byte encoding
        out.push_back(static_cast<uint8_t>(0x40 | 0x0F));
        uint64_t rem = nameIdx - 15;
        while (rem >= 128) {
            out.push_back(static_cast<uint8_t>(rem % 128 + 128));
            rem /= 128;
        }
        out.push_back(static_cast<uint8_t>(rem));
    }
    // Value as 7-bit-prefix string (no huffman)
    uint8_t len7 = static_cast<uint8_t>(value.size());
    if (value.size() < 128) {
        out.push_back(static_cast<uint8_t>(len7));
    } else {
        out.push_back(static_cast<uint8_t>(0x80 | (len7 & 0x7F)));
        uint64_t rem = value.size() - 128;
        while (rem >= 128) {
            out.push_back(static_cast<uint8_t>(rem % 128 + 128));
            rem /= 128;
        }
        out.push_back(static_cast<uint8_t>(rem));
    }
    out.insert(out.end(), value.begin(), value.end());
}

// Encode a QPACK header with literal name
static void EncodeLiteralName(std::vector<uint8_t>& out,
                              const std::string& name, const std::string& value) {
    // 0010xxxx: literal with literal name, never indexed
    // Low nibble = name length (if < 7) or 7 with continuation
    size_t nlen = name.size();
    if (nlen < 7) {
        out.push_back(static_cast<uint8_t>(0x20 | nlen));
    } else {
        out.push_back(0x27); // 0x20 | 7
        uint64_t rem = nlen - 7;
        while (rem >= 128) {
            out.push_back(static_cast<uint8_t>(rem % 128 + 128));
            rem /= 128;
        }
        out.push_back(static_cast<uint8_t>(rem));
    }
    out.insert(out.end(), name.begin(), name.end());
    // Value as 7-bit-prefix string
    if (value.size() < 128) {
        out.push_back(static_cast<uint8_t>(value.size()));
    } else {
        out.push_back(static_cast<uint8_t>(0x80 | (value.size() & 0x7F)));
        uint64_t rem = value.size() - 128;
        while (rem >= 128) {
            out.push_back(static_cast<uint8_t>(rem % 128 + 128));
            rem /= 128;
        }
        out.push_back(static_cast<uint8_t>(rem));
    }
    out.insert(out.end(), value.begin(), value.end());
}

// Encode auth request headers into QPACK
static std::vector<uint8_t> EncodeAuthHeaders(
    const std::string& authority, const std::string& auth) {
    std::vector<uint8_t> out;
    // Encoded Field Section prefix: Required Insert Count = 0, Base = 0
    out.push_back(0x00);
    out.push_back(0x00);

    // :method POST (static index 20)
    EncodeStaticNameRef(out, 20, "POST");
    // :path /auth (static index 1, value "/auth")
    EncodeStaticNameRef(out, 1, "/auth");
    // :scheme https (static index 23)
    EncodeStaticNameRef(out, 23, "https");
    // :authority (static index 0)
    EncodeStaticNameRef(out, 0, authority);
    // authorization (static index 80)
    EncodeStaticNameRef(out, 80, auth);

    return out;
}

// Decode a QPACK string with N-bit prefix
static std::string DecodeString(const uint8_t*& p, const uint8_t* end,
                                int prefixBits) {
    if (p >= end) throw std::runtime_error("h3_auth: truncated string");
    uint8_t first = *p;
    bool huffman = (first & 0x80) != 0;
    uint64_t len = first & ((1u << (prefixBits - 1)) - 1);
    int consumed = 1;
    if (len == static_cast<uint64_t>((1u << (prefixBits - 1)) - 1)) {
        // Multi-byte length
        len = 0;
        uint64_t shift = 0;
        for (;;) {
            if (p + consumed >= end) throw std::runtime_error("h3_auth: truncated int");
            uint8_t b = p[consumed++];
            len += static_cast<uint64_t>(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
    }
    p += consumed;
    if (p + len > end) throw std::runtime_error("h3_auth: string overflow");
    if (huffman) {
        std::string decoded = hy2::h3::HuffmanDecode(p, len);
        p += len;
        return decoded;
    }
    std::string result(reinterpret_cast<const char*>(p), len);
    p += len;
    return result;
}

// Decode QPACK-encoded headers
static std::vector<std::pair<std::string, std::string>>
DecodeQpackHeaders(const uint8_t* data, size_t len) {
    static const char* kStaticNames[] = {
        ":authority", ":path", "age", "content-disposition", "content-length",
        "cookie", "date", "etag", "if-modified-since", "if-none-match",
        "last-modified", "link", "location", "referer", "set-cookie",
        ":method", ":method", ":method", ":method", ":method",
        ":method", ":method", ":scheme", ":scheme", ":status",
        ":status", ":status", ":status", ":status", "accept",
        "accept", "accept-encoding", "accept-ranges",
        "access-control-allow-headers", "access-control-allow-headers",
        "access-control-allow-origin", "cache-control", "cache-control",
        "cache-control", "cache-control", "cache-control", "cache-control",
        "content-encoding", "content-encoding", "content-type",
        "content-type", "content-type", "content-type", "content-type",
        "content-type", "content-type", "content-type", "content-type",
        "range", "strict-transport-security", "strict-transport-security",
        "strict-transport-security", "vary", "vary",
        "x-content-type-options", "x-xss-protection", ":status",
        ":status", ":status", ":status", ":status", ":status",
        ":status", ":status", ":status", "accept-language",
        "access-control-allow-credentials", "access-control-allow-credentials",
        "access-control-allow-headers", "access-control-allow-methods",
        "access-control-allow-methods", "access-control-allow-methods",
        "access-control-expose-headers", "access-control-request-headers",
        "access-control-request-method", "access-control-request-method",
        "alt-svc", "authorization", "content-security-policy", "early-data",
        "expect-ct", "forwarded", "if-range", "origin", "purpose",
        "server", "timing-allow-origin", "upgrade-insecure-requests",
        "user-agent", "x-forwarded-for", "x-frame-options", "x-frame-options",
    };
    constexpr int kStaticCount = sizeof(kStaticNames) / sizeof(kStaticNames[0]);

    const uint8_t* p = data;
    const uint8_t* end = data + len;
    std::vector<std::pair<std::string, std::string>> out;

    // Skip Encoded Field Section prefix (2 bytes)
    if (len < 2) return out;
    p += 2;

    while (p < end) {
        uint8_t b = *p;
        if (b & 0x80) {
            // Indexed field line (static)
            uint64_t idx = ReadVarint(p, end);
            idx &= 0x3F; // strip high bits from first byte
            if (idx < static_cast<uint64_t>(kStaticCount)) {
                // For indexed, both name and value come from the static table
                // We need the actual static table values, not just names
                // For auth response, we only expect :status references
                static const char* kStaticValues[] = {
                    "", "/", "", "", "0", "", "", "", "", "",
                    "", "", "", "", "", "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS",
                    "POST", "PUT", "http", "https", "103",
                    "200", "304", "404", "503", "*/*",
                    "application/dns-message", "gzip, deflate, br", "bytes",
                    "cache-control", "content-type", "*", "max-age=0",
                    "max-age=2592000", "max-age=604800", "no-cache", "no-store",
                    "public, max-age=31536000", "br", "gzip",
                    "application/dns-message", "application/javascript",
                    "application/json", "application/x-www-form-urlencoded",
                    "image/gif", "image/jpeg", "image/png", "text/css",
                    "text/html; charset=utf-8", "text/plain",
                    "text/plain;charset=utf-8", "bytes=0-",
                    "max-age=31536000", "max-age=31536000; includesubdomains",
                    "max-age=31536000; includesubdomains; preload",
                    "accept-encoding", "origin", "nosniff", "1; mode=block",
                    "100", "204", "206", "302", "400",
                    "403", "421", "425", "500", "",
                    "FALSE", "TRUE", "*", "get",
                    "get, post, options", "options", "content-length",
                    "content-type", "get", "post", "clear", "",
                    "script-src 'none'; object-src 'none'; base-uri 'none'",
                    "1", "", "", "", "", "", "", "*", "prefetch",
                    "", "", "1", "", "deny", "sameorigin",
                };
                if (idx < static_cast<uint64_t>(kStaticCount)) {
                    out.emplace_back(kStaticNames[idx], kStaticValues[idx]);
                }
            }
        } else if ((b & 0xC0) == 0x40) {
            // Literal with static name reference
            ++p; // consume first byte
            uint64_t nameIdx = b & 0x0F;
            // Check for continuation
            if (nameIdx == 0x0F) {
                nameIdx = 0;
                uint64_t shift = 0;
                for (;;) {
                    if (p >= end) break;
                    uint8_t bb = *p++;
                    nameIdx += static_cast<uint64_t>(bb & 0x7F) << shift;
                    if (!(bb & 0x80)) break;
                    shift += 7;
                }
            }
            std::string value = DecodeString(p, end, 7);
            if (nameIdx < static_cast<uint64_t>(kStaticCount)) {
                out.emplace_back(kStaticNames[nameIdx], std::move(value));
            }
        } else if ((b & 0xE0) == 0x20) {
            // Literal with literal name
            ++p;
            std::string name = DecodeString(p, end, 4);
            std::string value = DecodeString(p, end, 7);
            out.emplace_back(std::move(name), std::move(value));
        } else {
            throw std::runtime_error("h3_auth: unsupported QPACK instruction");
        }
    }
    return out;
}

// Parse H3 response from a QUIC stream, returns status code and headers
struct H3Response {
    int statusCode = 0;
    std::vector<std::pair<std::string, std::string>> headers;
};

H3Response ParseH3Response(IQuicStream& stream) {
    H3Response resp;
    bool gotHeaders = false;

    for (int frameCount = 0; frameCount < 10; ++frameCount) {
        // Read frame type (varint)
        uint8_t typeBuf[8] = {};
        size_t n = stream.Read(typeBuf, 1);
        if (n == 0) {
            std::fprintf(stderr, "[dbg] H3Auth: stream EOF at frame %d\n", frameCount);
            break;
        }

        // Build full varint from first byte
        int typeLen = 1;
        uint64_t frameType = typeBuf[0] & 0x3F;
        int shift = 0;
        switch (typeBuf[0] >> 6) {
        case 0: break;
        case 1: typeLen = 2; shift = 8; break;
        case 2: typeLen = 4; shift = 24; break;
        case 3: typeLen = 8; shift = 56; break;
        }
        for (int i = 1; i < typeLen; ++i) {
            n = stream.Read(typeBuf + i, 1);
            if (n == 0) throw std::runtime_error("h3_auth: truncated frame type");
            frameType = (frameType << 8) | typeBuf[i];
        }

        // Read frame length (varint)
        uint8_t lenBuf[8] = {};
        n = stream.Read(lenBuf, 1);
        if (n == 0) throw std::runtime_error("h3_auth: truncated frame length");
        int lenLen = 1;
        uint64_t frameLen = lenBuf[0] & 0x3F;
        shift = 0;
        switch (lenBuf[0] >> 6) {
        case 0: break;
        case 1: lenLen = 2; shift = 8; break;
        case 2: lenLen = 4; shift = 24; break;
        case 3: lenLen = 8; shift = 56; break;
        }
        for (int i = 1; i < lenLen; ++i) {
            n = stream.Read(lenBuf + i, 1);
            if (n == 0) throw std::runtime_error("h3_auth: truncated frame length body");
            frameLen = (frameLen << 8) | lenBuf[i];
        }

        if (frameLen > (4u << 20)) {
            throw std::runtime_error("h3_auth: frame too large");
        }

        std::fprintf(stderr, "[dbg] H3Auth: frame %d type=%llu len=%llu\n",
                     frameCount, (unsigned long long)frameType, (unsigned long long)frameLen);

        // Read frame payload
        std::vector<uint8_t> payload(static_cast<size_t>(frameLen));
        size_t got = 0;
        while (got < payload.size()) {
            n = stream.Read(payload.data() + got, payload.size() - got);
            if (n == 0) throw std::runtime_error("h3_auth: truncated frame payload");
            got += n;
        }

        if (frameType == kFrameHeaders) {
            resp.headers = DecodeQpackHeaders(payload.data(), payload.size());
            for (auto& h : resp.headers) {
                if (h.first == ":status") {
                    resp.statusCode = std::atoi(h.second.c_str());
                }
            }
            gotHeaders = true;
            break; // Headers frame is enough for auth response
        }
        // DATA, SETTINGS, etc. - skip
    }

    if (!gotHeaders) {
        throw std::runtime_error("h3_auth: no HEADERS frame in response");
    }
    return resp;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// H3AuthRoundTripper

H3AuthRoundTripper::H3AuthRoundTripper(Params params)
    : params_(std::move(params)) {}

H3AuthRoundTripper::~H3AuthRoundTripper() = default;

client::ClientTransport::AuthResult H3AuthRoundTripper::RoundTrip(
    const client::Config& cfg, const proto::AuthRequest& req) {

    client::ClientTransport::AuthResult result;

    // Create a QUIC connection to the server
    auto conn = CreateQuicConnection(
        cfg.ServerAddr,
        cfg.TLSConfig.ServerName.empty() ? cfg.ServerAddr : cfg.TLSConfig.ServerName,
        cfg.QUICConfig,
        cfg.TLSConfig.InsecureSkipVerify);

    if (!conn) {
        throw ConnectError("failed to establish QUIC connection");
    }

    // A handshake that fails must not leave this connection behind: its
    // internal loop thread holds a strong self-reference, so dropping our
    // shared_ptr is not enough to destroy it - the connection (UDP socket and
    // thread included) stays alive until the QUIC idle timeout. Measured
    // 2026-10-11: a node prober walking four unreachable nodes had 30 live
    // connections after 25 s, one socket per ~1.2 s, and every failed pool
    // handshake did the same. CloseWithError() sets the flag the loop polls,
    // so the loop exits and the connection is really torn down.
    struct AbandonGuard {
        IQuicConnection* conn;
        bool handedOver = false;
        ~AbandonGuard() {
            if (!handedOver && conn) {
                try {
                    conn->CloseWithError(client::CloseErrCodeOK, "");
                } catch (...) {
                }
            }
        }
    } abandon{conn.get()};

    // Build auth headers matching Go client format
    // Go sends: Hysteria-Auth, Hysteria-CC-RX, Hysteria-Padding
    proto::HeaderMap hm;
    proto::AuthRequestToHeader(hm, req);

    std::vector<h3::Header> extraHeaders;
    for (auto& kv : hm) {
        extraHeaders.emplace_back(kv.first, kv.second);
    }

    // Use h3::Request which handles control stream, QPACK encoding,
    // and response parsing correctly (wire-compatible with Go server).
    auto resp = h3::Request(
        *conn,
        "POST",
        proto::URLHost,     // :authority = "hysteria"
        proto::URLPath,     // :path = "/auth"
        extraHeaders);

    result.StatusCode = resp.StatusCode;
    for (auto& h : resp.Headers) {
        result.Headers[h.first] = h.second;
    }
    // Success: the connection now belongs to the caller (ClientImpl::connect).
    abandon.handedOver = true;
    result.Conn = std::move(conn);

    return result;
}

std::vector<uint8_t> H3AuthRoundTripper::BuildAuthHeaders(
    const client::Config& cfg, const proto::AuthRequest& req) const {
    // Unused - auth encoding is now inline in RoundTrip
    return {};
}

std::vector<uint8_t> H3AuthRoundTripper::BuildSettingsFrame() const {
    // Unused - settings are now inline in RoundTrip
    return {};
}

proto::HeaderMap H3AuthRoundTripper::ParseResponseHeaders(
    const uint8_t* data, size_t len) const {
    // Unused - response parsing is now inline in RoundTrip
    return {};
}

int H3AuthRoundTripper::GetStatusCode(const proto::HeaderMap& headers) const {
    auto it = headers.find(":status");
    if (it == headers.end()) return 0;
    try {
        return std::stoi(it->second);
    } catch (...) {
        return 0;
    }
}

} // namespace hy2::quic_backend
