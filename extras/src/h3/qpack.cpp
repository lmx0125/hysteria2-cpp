#include "hy2/h3/qpack.hpp"

#include <cstring>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <algorithm>

// nghttp3 internal (but linkable) QPACK huffman tables - see
// third_party/nghttp3 lib/nghttp3_qpack_huffman.h / _data.c.
extern "C" {
typedef struct nghttp3_qpack_huffman_decode_node {
    uint16_t fstate;
    uint8_t flags;
    uint8_t sym;
} nghttp3_qpack_huffman_decode_node;

typedef struct nghttp3_qpack_huffman_sym {
    uint32_t nbits;
    uint32_t code;
} nghttp3_qpack_huffman_sym;

#define NGHTTP3_QPACK_HUFFMAN_FLAG_ACCEPTED 0x01U
#define NGHTTP3_QPACK_HUFFMAN_FLAG_SYM 0x02U

extern const nghttp3_qpack_huffman_decode_node qpack_huffman_decode_table[][16];
extern const nghttp3_qpack_huffman_sym huffman_sym_table[];
}

namespace hy2::h3 {

namespace {

constexpr uint8_t kHuffAccepted = NGHTTP3_QPACK_HUFFMAN_FLAG_ACCEPTED;
constexpr uint8_t kHuffSym = NGHTTP3_QPACK_HUFFMAN_FLAG_SYM;
constexpr uint16_t kHuffFailState = 256;

// ---------------------------------------------------------------------------
// Integer decoding (HPACK 搂5.1 / QPACK 搂4.1.1), N-bit prefix, MSB-continuation
// ---------------------------------------------------------------------------
uint64_t DecodeInt(const uint8_t*& p, const uint8_t* end, int prefixBits) {
    if (p >= end) throw std::runtime_error("qpack: truncated integer");
    uint64_t value = (*p) & ((1u << prefixBits) - 1);
    ++p;
    if (value < static_cast<uint64_t>((1u << prefixBits) - 1)) return value;
    uint64_t mult = 0;
    for (;;) {
        if (p >= end) throw std::runtime_error("qpack: truncated int cont");
        uint8_t b = *p++;
        value += static_cast<uint64_t>(b & 0x7F) << mult;
        if (!(b & 0x80)) break;
        mult += 7;
        if (mult > 56) throw std::runtime_error("qpack: integer too long");
    }
    return value;
}

void AppendInt(std::vector<uint8_t>& out, uint8_t firstByteMasked,
               int prefixBits, uint64_t value) {
    uint64_t maxDirect = (1ull << prefixBits) - 1;
    if (value < maxDirect) {
        out.push_back(firstByteMasked | static_cast<uint8_t>(value));
        return;
    }
    out.push_back(firstByteMasked | static_cast<uint8_t>(maxDirect));
    value -= maxDirect;
    while (value >= 128) {
        out.push_back(static_cast<uint8_t>(value % 128 + 128));
        value /= 128;
    }
    out.push_back(static_cast<uint8_t>(value));
}

// ---------------------------------------------------------------------------
// Huffman decode via nghttp3 nibble state machine
// ---------------------------------------------------------------------------
std::string HuffmanDecode(const uint8_t* src, size_t len) {
    std::string out;
    out.reserve(len * 2);
    uint16_t fstate = 0;      // root
    uint8_t lastFlags = kHuffAccepted;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = src[i];
        for (int shift : {4, 0}) {
            const auto& node =
                qpack_huffman_decode_table[fstate][(c >> shift) & 0xF];
            fstate = node.fstate;
            lastFlags = node.flags;
            if (node.flags & kHuffSym) {
                out.push_back(static_cast<char>(node.sym));
            }
            if (fstate == kHuffFailState) {
                throw std::runtime_error("qpack: huffman decode error");
            }
        }
    }
    if (!(lastFlags & kHuffAccepted)) {
        if (std::getenv("HY2_QUIC_DEBUG")) {
            std::fprintf(stderr, "[qpack] huff-fail %zu bytes:", len);
            for (size_t i = 0; i < len && i < 24; ++i)
                std::fprintf(stderr, " %02x", src[i]);
            std::fprintf(stderr, " lastFlags=%u out=%.*s\n", lastFlags,
                         (int)out.size(), out.c_str());
        }
        throw std::runtime_error("qpack: huffman EOS not accepted");
    }
    return out;
}

std::string HuffmanEncode(const uint8_t* src, size_t len) {
    // Bit-writer using nghttp3's canonical symbol table (MSB-aligned codes).
    std::vector<uint8_t> out;
    uint64_t acc = 0;
    int nbits = 0;
    for (size_t i = 0; i < len; ++i) {
        const auto& sym = huffman_sym_table[src[i]];
        uint32_t code = sym.nbits ? (sym.code >> (32 - sym.nbits)) : 0;
        acc = (acc << sym.nbits) | code;
        nbits += static_cast<int>(sym.nbits);
        while (nbits >= 8) {
            nbits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> nbits) & 0xFF));
        }
    }
    if (nbits > 0) { // pad with 1s
        acc = (acc << (8 - nbits)) | ((1u << (8 - nbits)) - 1);
        out.push_back(static_cast<uint8_t>(acc & 0xFF));
    }
    return std::string(out.begin(), out.end());
}

// String literal with N-bit length prefix. When preFirst >= 0 the first
// prefix group came from the instruction byte's low nibble (p already past).
std::string DecodeString(const uint8_t*& p, const uint8_t* end, int prefixBits,
                         int preFirst = -1) {
    bool huffman;
    uint64_t len;
    if (preFirst >= 0) {
        int huffBit = 1 << (prefixBits - 1);
        huffman = (preFirst & huffBit) != 0;
        len = static_cast<uint64_t>(preFirst & (huffBit - 1));
        if (std::getenv("HY2_QUIC_DEBUG"))
            std::fprintf(stderr, "[qpack] preFirst=%02x h=%d len0=%llu\n",
                         preFirst, (int)huffman, (unsigned long long)len);
        if (len == static_cast<uint64_t>(huffBit - 1)) {
            uint64_t mult = 0;
            for (;;) {
                if (p >= end) throw std::runtime_error("qpack: trunc str cont");
                uint8_t b = *p++;
                len += static_cast<uint64_t>(b & 0x7F) << mult;
                if (!(b & 0x80)) break;
                mult += 7;
                if (mult > 56) throw std::runtime_error("qpack: str len long");
            }
        }
    } else {
        if (p >= end) throw std::runtime_error("qpack: truncated string");
        huffman = (*p & 0x80) != 0;
        len = DecodeInt(p, end, prefixBits);
    }
    if (p + len > end) throw std::runtime_error("qpack: string overflow");
    std::string raw(reinterpret_cast<const char*>(p), static_cast<size_t>(len));
    p += len;
    return huffman ? HuffmanDecode(reinterpret_cast<const uint8_t*>(raw.data()),
                                   raw.size())
                   : raw;
}

void EncodeString(std::vector<uint8_t>& out, const std::string& s,
                  int prefixBits, bool allowHuffman) {
    std::string payload = s;
    bool useHuff = false;
    if (allowHuffman && !s.empty()) {
        auto h = HuffmanEncode(reinterpret_cast<const uint8_t*>(s.data()),
                               s.size());
        if (h.size() < s.size()) {
            payload = std::move(h);
            useHuff = true;
        }
    }
    uint8_t mask = useHuff ? 0x80 : 0x00;
    AppendInt(out, mask, prefixBits, payload.size());
    out.insert(out.end(), payload.begin(), payload.end());
}

// NOTE: nghttp3's huffman_sym_table stores codes ALIGNED TO THE MSB of a
// 32-bit word despite its comment saying otherwise (verified empirically:
// 'h' -> nbits=6, code=0x9C000000).

// ---------------------------------------------------------------------------
// Static table (RFC 9204 Appendix A)
// ---------------------------------------------------------------------------
struct StaticEntry { const char* name; const char* value; };
constexpr StaticEntry kStatic[] = {
    {":authority", ""},                                   // 0
    {":path", "/"},                                       // 1
    {"age", "0"},
    {"content-disposition", ""},
    {"content-length", "0"},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"referer", ""},
    {"set-cookie", ""},
    {":method", "CONNECT"},                               // 15
    {":method", "DELETE"},
    {":method", "GET"},
    {":method", "HEAD"},
    {":method", "OPTIONS"},
    {":method", "POST"},                                  // 20
    {":method", "PUT"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "103"},
    {":status", "200"},
    {":status", "304"},
    {":status", "404"},
    {":status", "503"},
    {"accept", "*/*"},                                    // 29
    {"accept", "application/dns-message"},
    {"accept-encoding", "gzip, deflate, br"},
    {"accept-ranges", "bytes"},
    {"access-control-allow-headers", "cache-control"},
    {"access-control-allow-headers", "content-type"},
    {"access-control-allow-origin", "*"},
    {"cache-control", "max-age=0"},
    {"cache-control", "max-age=2592000"},
    {"cache-control", "max-age=604800"},
    {"cache-control", "no-cache"},
    {"cache-control", "no-store"},
    {"cache-control", "public, max-age=31536000"},
    {"content-encoding", "br"},
    {"content-encoding", "gzip"},
    {"content-type", "application/dns-message"},
    {"content-type", "application/javascript"},
    {"content-type", "application/json"},
    {"content-type", "application/x-www-form-urlencoded"},
    {"content-type", "image/gif"},
    {"content-type", "image/jpeg"},
    {"content-type", "image/png"},
    {"content-type", "text/css"},
    {"content-type", "text/html; charset=utf-8"},
    {"content-type", "text/plain"},
    {"content-type", "text/plain;charset=utf-8"},
    {"range", "bytes=0-"},
    {"strict-transport-security", "max-age=31536000"},
    {"strict-transport-security", "max-age=31536000; includesubdomains"},
    {"strict-transport-security",
     "max-age=31536000; includesubdomains; preload"},
    {"vary", "accept-encoding"},
    {"vary", "origin"},
    {"x-content-type-options", "nosniff"},
    {"x-xss-protection", "1; mode=block"},
    {":status", "100"},
    {":status", "204"},
    {":status", "206"},
    {":status", "302"},
    {":status", "400"},
    {":status", "403"},
    {":status", "421"},
    {":status", "425"},
    {":status", "500"},
    {"accept-language", ""},
    {"access-control-allow-credentials", "FALSE"},
    {"access-control-allow-credentials", "TRUE"},
    {"access-control-allow-headers", "*"},
    {"access-control-allow-methods", "get"},
    {"access-control-allow-methods", "get, post, options"},
    {"access-control-allow-methods", "options"},
    {"access-control-expose-headers", "content-length"},
    {"access-control-request-headers", "content-type"},
    {"access-control-request-method", "get"},
    {"access-control-request-method", "post"},
    {"alt-svc", "clear"},
    {"authorization", ""},
    {"content-security-policy",
     "script-src 'none'; object-src 'none'; base-uri 'none'"},
    {"early-data", "1"},
    {"expect-ct", ""},
    {"forwarded", ""},
    {"if-range", ""},
    {"origin", ""},
    {"purpose", "prefetch"},
    {"server", ""},
    {"timing-allow-origin", "*"},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", ""},
    {"x-forwarded-for", ""},
    {"x-frame-options", "deny"},
    {"x-frame-options", "sameorigin"},
};
constexpr int kStaticCount = sizeof(kStatic) / sizeof(kStatic[0]);

} // namespace

std::string QpackStaticName(int index) {
    if (index < 0 || index >= kStaticCount) return "";
    return kStatic[index].name;
}

// Debug helper: hex of the huffman encoding of s.
std::string QpackDebugHuffmanHex(const std::string& s) {
    if (!s.empty()) {
        const auto& sy0 = huffman_sym_table[static_cast<unsigned char>(s[0])];
        std::fprintf(stderr, "[qpack] sym '%c' nbits=%u code=%u\n", s[0],
                     sy0.nbits, sy0.code);
    }
    auto h = HuffmanEncode(reinterpret_cast<const uint8_t*>(s.data()),
                           s.size());
    std::string hex;
    char buf[4];
    for (unsigned char c : h) {
        snprintf(buf, sizeof(buf), "%02x", c);
        hex += buf;
    }
    return hex;
}

// Debug helper: trace decoding raw huffman bytes.
std::string QpackDebugHuffmanTrace(const uint8_t* src, size_t len) {
    uint16_t fstate = 0;
    uint8_t lastFlags = NGHTTP3_QPACK_HUFFMAN_FLAG_ACCEPTED;
    std::string out;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = src[i];
        for (int shift : {4, 0}) {
            const auto& node =
                qpack_huffman_decode_table[fstate][(c >> shift) & 0xF];
            fstate = node.fstate;
            lastFlags = node.flags;
            if (node.flags & NGHTTP3_QPACK_HUFFMAN_FLAG_SYM)
                out.push_back(static_cast<char>(node.sym));
            std::fprintf(stderr,
                         "[qpack-trace] byte=%02x nib=%u -> fs=%u fl=%u sym=%c\n",
                         c, (c >> shift) & 0xF, fstate, node.flags,
                         (node.flags & NGHTTP3_QPACK_HUFFMAN_FLAG_SYM)
                             ? node.sym
                             : '.');
        }
    }
    return out;
}

int QpackStaticIndex(const std::string& name, const std::string& value) {
    for (int i = 0; i < kStaticCount; ++i) {
        if (name == kStatic[i].name && value == kStatic[i].value) return i;
    }
    return -1;
}

std::vector<Header> QpackDecode(const uint8_t* data, size_t len) {
    const uint8_t* p = data;
    const uint8_t* end = data + len;
    std::vector<Header> out;

    if (std::getenv("HY2_QUIC_DEBUG") && len > 2) {
        std::fprintf(stderr, "[qpack] dec %zu bytes:", len);
        for (size_t i = 2; i < std::min(len, size_t{26}); ++i)
            std::fprintf(stderr, " %02x", data[i]);
        std::fprintf(stderr, "\n");
    }

    // ---- Encoded Field Section prefix (RFC 9204 搂4.5.1) ----
    // Required Insert Count: 8-bit-prefix integer. Non-zero implies the
    // encoder used the dynamic table - which we never negotiate.
    uint64_t ric = DecodeInt(p, end, 8);
    if (ric != 0) {
        throw std::runtime_error("qpack: dynamic table in use (RIC=" +
                                 std::to_string(ric) + ")");
    }
    // Base: sign bit + 7-bit-prefix Delta Base. Irrelevant for static-only.
    (void)DecodeInt(p, end, 7);

    while (p < end) {
        uint8_t b = *p;
        if (b & 0x80) {
            // Indexed Field Line (T=static only; we never negotiate dynamic).
            uint64_t index = DecodeInt(p, end, 6);
            if (index >= static_cast<uint64_t>(kStaticCount)) {
                throw std::runtime_error("qpack: unsupported index " +
                                         std::to_string(index));
            }
            out.emplace_back(kStatic[index].name, kStatic[index].value);
        } else if ((b & 0xC0) == 0x40) {
            // Literal Field Line with Name Reference.
            bool staticRef = (b & 0x10) != 0;
            uint64_t nameIdx = DecodeInt(p, end, 4);
            if (!staticRef || nameIdx >= static_cast<uint64_t>(kStaticCount)) {
                throw std::runtime_error("qpack: non-static name ref");
            }
            std::string value = DecodeString(p, end, 7);
            if (std::getenv("HY2_QUIC_DEBUG")) {
                std::fprintf(stderr, "[qpack] +ref %s=%.*s\n",
                             kStatic[nameIdx].name,
                             (int)std::min<size_t>(40, value.size()),
                             value.c_str());
            }
            out.emplace_back(kStatic[nameIdx].name, std::move(value));
        } else if ((b & 0xE0) == 0x20) {
            // Literal Field Line with Literal Name (RFC 9204 §4.5.6):
            //   '001' + N bit; the LOW NIBBLE of this same byte is the
            //   first group of the name's 4-bit-prefix string literal
            //   (H flag + 3-bit length), then an 8-bit-prefix value.
            ++p; // consume the instruction byte itself
            std::string name = DecodeString(p, end, 4, b & 0x0F);
            std::string value = DecodeString(p, end, 7);
            if (std::getenv("HY2_QUIC_DEBUG")) {
                std::fprintf(stderr, "[qpack] +lit %s=%.*s\n", name.c_str(),
                             (int)std::min<size_t>(40, value.size()),
                             value.c_str());
            }
            out.emplace_back(std::move(name), std::move(value));
        } else {
            throw std::runtime_error("qpack: unsupported instruction (dynamic?)");
        }
    }
    return out;
}

std::vector<uint8_t> QpackEncode(const std::vector<Header>& headers) {
    std::vector<uint8_t> out;
    out.reserve(128);

    // Encoded Field Section prefix (RFC 9204 搂4.5.1):
    //   Required Insert Count = 0 (static-only encoding)
    //   Sign = 0, Delta Base = 0
    out.push_back(0x00);
    out.push_back(0x00);

    for (const auto& kv : headers) {
        // Full match against the static table 鈫?indexed field line.
        int idx = QpackStaticIndex(kv.first, kv.second);
        if (idx >= 0) {
            AppendInt(out, 0xC0, 6, static_cast<uint64_t>(idx));
            continue;
        }
        // Static name match 鈫?literal with (static) name reference.
        int nameIdx = -1;
        for (int i = 0; i < kStaticCount; ++i) {
            if (kv.first == kStatic[i].name) { nameIdx = i; break; }
        }
        if (nameIdx >= 0) {
            AppendInt(out, 0x50, 4, static_cast<uint64_t>(nameIdx)); // T=1
            EncodeString(out, kv.second, 7, /*allowHuffman=*/false);
        } else {
            // '001'+N(0) shares the byte with the name's 4-bit prefix:
            // combined = 0x20 | (H<<3) | len_hi3 (continuation follows).
            std::string namePayload = kv.first; // raw, no huffman
            size_t nlen = namePayload.size();
            if (nlen < 7) {
                out.push_back(static_cast<uint8_t>(0x20 | nlen));
            } else {
                out.push_back(0x27); // 0x20 | 7 → continuation
                uint64_t rem = nlen - 7;
                while (rem >= 128) {
                    out.push_back(static_cast<uint8_t>(rem % 128 + 128));
                    rem /= 128;
                }
                out.push_back(static_cast<uint8_t>(rem));
            }
            out.insert(out.end(), namePayload.begin(), namePayload.end());
            EncodeString(out, kv.second, 7, /*allowHuffman=*/false);
        }
    }
    return out;
}

} // namespace hy2::h3



