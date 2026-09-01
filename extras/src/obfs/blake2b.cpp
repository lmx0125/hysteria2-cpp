// blake2b.cpp - BLAKE2b-256 per RFC 7693 (digest_length=32, key_length=0,
// fanout=1, depth=1). Portable, dependency-free, well-defined for MSVC /W4.
#include "hy2/obfs/blake2b.hpp"

#include <cstring>

namespace hy2::crypto {
namespace {

constexpr size_t kBlockLen = 128;

constexpr uint64_t kIV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

constexpr uint8_t kSigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    // Rounds 10 and 11 reuse rows 0 and 1 (RFC 7693).
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

inline uint64_t RotR64(uint64_t x, unsigned c) { return (x >> c) | (x << (64 - c)); }

inline uint64_t LoadLE64(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) | (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) | (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) | (static_cast<uint64_t>(p[7]) << 56);
}

// Compress one 128-byte block. t is the total number of message bytes
// compressed so far INCLUDING this block; last enables the finalization flag.
void Compress(uint64_t h[8], const uint8_t* block, uint64_t t, bool last) {
    uint64_t v[16];
    for (int i = 0; i < 8; i++) v[i] = h[i];
    for (int i = 0; i < 8; i++) v[8 + i] = kIV[i];
    v[12] ^= t;
    v[14] ^= last ? ~static_cast<uint64_t>(0) : 0;

    uint64_t m[16];
    for (int i = 0; i < 16; i++) m[i] = LoadLE64(block + 8 * i);

    auto G = [&](int a, int b, int c, int d, uint64_t x, uint64_t y) {
        v[a] += v[b] + x;
        v[d] ^= v[a];
        v[d] = RotR64(v[d], 32);
        v[c] += v[d];
        v[b] ^= v[c];
        v[b] = RotR64(v[b], 24);
        v[a] += v[b] + y;
        v[d] ^= v[a];
        v[d] = RotR64(v[d], 16);
        v[c] += v[d];
        v[b] ^= v[c];
        v[b] = RotR64(v[b], 63);
    };

    for (int r = 0; r < 12; r++) {
        const uint8_t* s = kSigma[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

} // namespace

Digest256 Blake2bSum256(const uint8_t* data, size_t len) {
    uint64_t h[8];
    for (int i = 0; i < 8; i++) h[i] = kIV[i];
    // Parameter block: 0x01010000 | key_length(0)<<8 | digest_length(32)
    // (fanout=1, depth=1 in the high bytes).
    h[0] ^= 0x01010000ULL ^ 32ULL;

    uint8_t buf[kBlockLen];
    size_t fill = 0;
    uint64_t t = 0;

    while (len > 0) {
        size_t take = kBlockLen - fill;
        if (take > len) take = len;
        std::memcpy(buf + fill, data, take);
        fill += take;
        data += take;
        len -= take;
        if (fill == kBlockLen && len > 0) {
            t += kBlockLen;
            Compress(h, buf, t, false);
            fill = 0;
        }
    }
    // Final block: always compress the buffer (zero-padded), even when empty.
    t += fill;
    if (fill < kBlockLen) std::memset(buf + fill, 0, kBlockLen - fill);
    Compress(h, buf, t, true);

    Digest256 out{};
    // Extract 32 bytes from 4 x uint64_t LE (h[0..3]), unrolled for performance.
    for (int i = 0; i < 4; i++) {
        uint64_t v = h[i];
        out.b[i * 8 + 0] = static_cast<uint8_t>(v);
        out.b[i * 8 + 1] = static_cast<uint8_t>(v >> 8);
        out.b[i * 8 + 2] = static_cast<uint8_t>(v >> 16);
        out.b[i * 8 + 3] = static_cast<uint8_t>(v >> 24);
        out.b[i * 8 + 4] = static_cast<uint8_t>(v >> 32);
        out.b[i * 8 + 5] = static_cast<uint8_t>(v >> 40);
        out.b[i * 8 + 6] = static_cast<uint8_t>(v >> 48);
        out.b[i * 8 + 7] = static_cast<uint8_t>(v >> 56);
    }
    return out;
}

} // namespace hy2::crypto
