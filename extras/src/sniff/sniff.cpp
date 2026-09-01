// sniff.cpp - rewrite of extras/sniff/sniff.go.
#include "hy2/sniff/sniff.hpp"

#include <algorithm>
#include <cstring>

#include "hy2/error.hpp"
#include "hy2/sniff/quic_initial.hpp"

namespace hy2::sniff {

namespace {

// strconv.Atoi subset: optional sign + digits, fits in int64.
bool asciiAtoi(const std::string& s, long long& out) {
    size_t i = 0;
    bool neg = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        neg = s[i] == '-';
        i++;
    }
    if (i >= s.size()) return false;
    long long v = 0;
    for (; i < s.size(); i++) {
        char c = s[i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
        if (v > 922337203685477580) return false; // overflow guard
    }
    out = neg ? -v : v;
    return true;
}

// io.ReadFull that returns whatever it got on clean EOF (the Go sniffer
// swallows the error and uses the partial buffer).
size_t readFullPartial(IByteReader& r, uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        size_t got = r.Read(buf + off, n - off);
        if (got == 0) break;
        off += got;
    }
    return off;
}

// Finds the "\r\n\r\n" header terminator, if present.
size_t findHeaderEnd(const std::vector<uint8_t>& buf) {
    if (buf.size() < 4) return std::string::npos;
    for (size_t i = 0; i + 4 <= buf.size(); i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return i;
        }
    }
    return std::string::npos;
}

bool asciiEqualsNoCase(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

std::string_view trimSpaces(std::string_view v) {
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
    return v;
}

// Minimal http.ReadRequest equivalent: parses the request line and headers
// from the buffered head and extracts the Host header value (first one
// wins). Returns nullopt when the request can't be parsed (Go: req == nil).
std::optional<std::string> parseHttpRequestHost(const uint8_t* d, size_t n) {
    size_t pos = 0;
    bool firstLine = true;
    std::string host;
    bool haveHost = false;
    while (pos < n) {
        const void* nl = std::memchr(d + pos, '\n', n - pos);
        if (nl == nullptr) return std::nullopt; // no terminating blank line
        size_t eol = static_cast<size_t>(static_cast<const uint8_t*>(nl) - d);
        size_t lineLen = eol - pos;
        if (lineLen > 0 && d[pos + lineLen - 1] == '\r') lineLen--;
        std::string_view line(reinterpret_cast<const char*>(d) + pos, lineLen);
        pos = eol + 1;

        if (firstLine) {
            firstLine = false;
            // METHOD SP REQUEST-URI SP HTTP/x.y
            size_t sp1 = line.find(' ');
            if (sp1 == std::string_view::npos) return std::nullopt;
            size_t sp2 = line.rfind(' ');
            if (sp2 == std::string_view::npos || sp2 <= sp1) return std::nullopt;
            if (line.compare(sp2 + 1, 5, "HTTP/") != 0) return std::nullopt;
            continue;
        }
        if (line.empty()) break; // end of headers
        if (line[0] == ' ' || line[0] == '\t') continue; // obsolete folding
        size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0) return std::nullopt;
        if (!asciiEqualsNoCase(line.substr(0, colon), "Host")) continue;
        if (haveHost) continue; // first occurrence wins (Header.Get)
        host.assign(trimSpaces(line.substr(colon + 1)));
        haveHost = true;
    }
    if (firstLine) return std::nullopt;
    if (!haveHost) return std::string{};
    return host;
}

} // namespace

bool Sniffer::isHTTP(const uint8_t* buf, size_t len) {
    if (len < 3) return false;
    // First 3 bytes should be English letters (whatever HTTP method)
    for (size_t i = 0; i < 3; i++) {
        uint8_t b = buf[i];
        if ((b < 'A' || b > 'Z') && (b < 'a' || b > 'z')) return false;
    }
    return true;
}

bool Sniffer::isTLS(const uint8_t* buf, size_t len) {
    if (len < 3) return false;
    return buf[0] >= 0x16 && buf[0] <= 0x17 && buf[1] == 0x03 && buf[2] <= 0x09;
}

bool Sniffer::Check(bool isUDP, const std::string& reqAddr) {
    // @ means it's internal (e.g. speed test)
    if (!reqAddr.empty() && reqAddr[0] == '@') return false;
    auto hp = SplitHostPort(reqAddr);
    if (!hp) return false;
    if (!RewriteDomain && !IsIP(hp->first)) {
        // Is a domain and domain rewriting is disabled
        return false;
    }
    long long portNum;
    if (!asciiAtoi(hp->second, portNum)) return false;
    const PortUnion& ports = isUDP ? UDPPorts : TCPPorts;
    return ports.empty() || PortUnionContains(ports, static_cast<uint16_t>(portNum));
}

std::vector<uint8_t> Sniffer::TCP(IHyStream& stream, std::string& reqAddr) {
    Duration timeout = Timeout.ns == 0 ? kSniffDefaultTimeout : Timeout;
    stream.SetReadDeadline(MonoTime::Now().Add(timeout.ns));
    // Make sure to reset the deadline after sniffing
    struct DeadlineReset {
        IHyStream& s;
        ~DeadlineReset() { s.SetReadDeadline(MonoTime{}); }
    } reset{stream};

    // Read 3 bytes to determine the protocol
    uint8_t pre[3];
    size_t got = readFullPartial(stream, pre, 3);
    std::vector<uint8_t> putback(pre, pre + got);

    if (got < 3) {
        // Not enough within the timeout, just return what we have
        return putback;
    }

    if (isHTTP(pre, got)) {
        // HTTP. Mirrors bufio over io.LimitReader(teeReader): pull up to 4096
        // byte chunks until headers are complete or the limit is reached,
        // keeping everything read for the putback buffer.
        bool haveEnd = findHeaderEnd(putback) != std::string::npos;
        while (!haveEnd && putback.size() < kSniffMaxHTTPHeaderBytes) {
            uint8_t chunk[4096];
            size_t want =
                std::min(sizeof(chunk), kSniffMaxHTTPHeaderBytes - putback.size());
            size_t n = stream.Read(chunk, want);
            if (n == 0) break;
            putback.insert(putback.end(), chunk, chunk + n);
            haveEnd = findHeaderEnd(putback) != std::string::npos;
        }
        auto hostOpt = parseHttpRequestHost(putback.data(), putback.size());
        if (hostOpt && !hostOpt->empty()) {
            // Host can be host:port, in which case we need to extract the host part
            std::string msg;
            std::string host;
            auto hsp = SplitHostPort(*hostOpt, msg);
            if (hsp) {
                host = hsp->first;
            } else {
                // No port, just use the whole string
                host = *hostOpt;
            }
            auto cur = SplitHostPort(reqAddr, msg);
            if (!cur) throw Error(msg);
            reqAddr = JoinHostPort(host, cur->second);
        }
        return putback;
    } else if (isTLS(pre, got)) {
        // TLS. Need to read 2 more bytes (content length)
        uint8_t hdr[2];
        size_t g2 = readFullPartial(stream, hdr, 2);
        putback.insert(putback.end(), hdr, hdr + g2);
        if (g2 < 2) {
            // Not enough within the timeout, just return what we have
            return putback;
        }
        size_t contentLength = (static_cast<size_t>(putback[3]) << 8) | putback[4];
        size_t before = putback.size();
        putback.resize(before + contentLength);
        size_t g3 = readFullPartial(stream, putback.data() + before, contentLength);
        putback.resize(before + g3);
        if (g3 < contentLength) {
            // Not enough within the timeout, just return what we have
            return putback;
        }
        auto sni = UnmarshalClientHelloSNI(putback.data() + 5, putback.size() - 5);
        if (sni && !sni->empty()) {
            std::string msg;
            auto cur = SplitHostPort(reqAddr, msg);
            if (!cur) throw Error(msg);
            reqAddr = JoinHostPort(*sni, cur->second);
        }
        return putback;
    } else {
        // Unrecognized protocol, just return what we have
        return putback;
    }
}

void Sniffer::UDP(std::vector<uint8_t>& data, std::string& reqAddr) {
    // Decrypt QUIC Initial packet to extract SNI (matches Go's sniff/internal/quic).
    if (data.empty()) return;

    // Check if this looks like a QUIC Initial packet
    if (!IsQuicInitial(data.data(), data.size())) return;

    std::string sni = ExtractQuicSNI(data.data(), data.size());
    if (!sni.empty()) {
        // Rewrite the address with the SNI hostname
        std::string msg;
        auto cur = SplitHostPort(reqAddr, msg);
        if (!cur) return;
        reqAddr = JoinHostPort(sni, cur->second);
    }
}

std::optional<std::string> UnmarshalClientHelloSNI(const uint8_t* data, size_t len) {
    // Strict parse mirroring utls.UnmarshalClientHello:
    // exact handshake length match required.
    if (len < 4) return std::nullopt;
    if (data[0] != 0x01) return std::nullopt; // typeClientHello
    size_t hsLen =
        (static_cast<size_t>(data[1]) << 16) | (static_cast<size_t>(data[2]) << 8) |
        data[3];
    if (hsLen + 4 != len) return std::nullopt;

    const uint8_t* b = data + 4;
    size_t bl = hsLen;
    size_t pos = 0;
    auto need = [&](size_t k) { return pos + k <= bl; };

    if (!need(2)) return std::nullopt; // client version
    pos += 2;
    if (!need(32)) return std::nullopt; // random
    pos += 32;
    if (!need(1)) return std::nullopt;
    size_t sessionIdLen = b[pos++];
    if (!need(sessionIdLen)) return std::nullopt;
    pos += sessionIdLen;
    if (!need(2)) return std::nullopt;
    size_t cipherSuitesLen = (static_cast<size_t>(b[pos]) << 8) | b[pos + 1];
    pos += 2;
    if (!need(cipherSuitesLen)) return std::nullopt;
    pos += cipherSuitesLen;
    if (!need(1)) return std::nullopt;
    size_t compressionMethodsLen = b[pos++];
    if (!need(compressionMethodsLen)) return std::nullopt;
    pos += compressionMethodsLen;
    if (!need(2)) return std::nullopt;
    size_t extensionsTotal = (static_cast<size_t>(b[pos]) << 8) | b[pos + 1];
    pos += 2;
    // Extensions fill the rest of the message exactly.
    if (extensionsTotal != bl - pos) return std::nullopt;

    std::optional<std::string> sni;
    size_t extEnd = bl;
    while (pos < extEnd) {
        if (extEnd - pos < 4) return std::nullopt;
        size_t extType = (static_cast<size_t>(b[pos]) << 8) | b[pos + 1];
        size_t extLen = (static_cast<size_t>(b[pos + 2]) << 8) | b[pos + 3];
        pos += 4;
        if (extEnd - pos < extLen) return std::nullopt;

        if (extType == 0x0000) { // extensionServerName
            const uint8_t* sd = b + pos;
            size_t sl = extLen;
            if (sl < 2) return std::nullopt;
            size_t namesListLen = (static_cast<size_t>(sd[0]) << 8) | sd[1];
            if (namesListLen + 2 != sl) return std::nullopt;
            size_t sp = 2;
            while (sp < sl) {
                if (sl - sp < 3) return std::nullopt;
                uint8_t nameType = sd[sp];
                size_t nameLen = (static_cast<size_t>(sd[sp + 1]) << 8) | sd[sp + 2];
                sp += 3;
                if (sl - sp < nameLen) return std::nullopt;
                if (nameType == 0) {
                    std::string name(reinterpret_cast<const char*>(sd) + sp, nameLen);
                    // An SNI value may not include a trailing dot.
                    if (!name.empty() && name.back() == '.') name.pop_back();
                    sni = std::move(name); // last host_name entry wins
                }
                sp += nameLen;
            }
        }
        pos += extLen;
    }
    return sni;
}

} // namespace hy2::sniff
