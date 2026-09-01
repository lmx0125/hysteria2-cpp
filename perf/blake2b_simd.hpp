// blake2b_simd.hpp - SIMD 加速的 BLAKE2b-256 实现
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#ifdef _MSC_VER
#include <intrin.h>
#endif

#if defined(__AVX2__) || defined(_MSC_VER)
#define HY2_HAS_AVX2 1
#include <immintrin.h>
#elif defined(__SSE2__)
#define HY2_HAS_SSE2 1
#include <emmintrin.h>
#endif

namespace hy2::perf {

alignas(32) static constexpr uint64_t kBlake2bIV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static constexpr uint8_t kSigma[12][16] = {
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
    {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},
    {7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
    {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},
    {2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
    {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},
    {13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
    {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},
    {10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0},
    {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},
    {14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
};

// 64-bit right rotation
#ifdef _MSC_VER
#define HY2_ROTR64(x, n) _rotr64(x, n)
#else
#define HY2_ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#endif

static inline void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d,
                     uint64_t x, uint64_t y) {
    a = a + b + x;
    d = HY2_ROTR64(d ^ a, 32);
    c = c + d;
    b = HY2_ROTR64(b ^ c, 24);
    a = a + b + y;
    d = HY2_ROTR64(d ^ a, 16);
    c = c + d;
    b = HY2_ROTR64(b ^ c, 63);
}

static inline void Compress(uint64_t state[8], const uint64_t block[16],
                            uint64_t t0, bool last) {
    uint64_t v[16];
    for (int i = 0; i < 8; ++i) v[i] = state[i];
    v[8]  = kBlake2bIV[0];
    v[9]  = kBlake2bIV[1];
    v[10] = kBlake2bIV[2];
    v[11] = kBlake2bIV[3];
    v[12] = kBlake2bIV[4] ^ t0;
    v[13] = kBlake2bIV[5];
    v[14] = last ? ~kBlake2bIV[6] : kBlake2bIV[6];
    v[15] = kBlake2bIV[7];

    for (int round = 0; round < 12; ++round) {
        const uint8_t* s = kSigma[round];
        G(v[0], v[4], v[8],  v[12], block[s[0]],  block[s[1]]);
        G(v[1], v[5], v[9],  v[13], block[s[2]],  block[s[3]]);
        G(v[2], v[6], v[10], v[14], block[s[4]],  block[s[5]]);
        G(v[3], v[7], v[11], v[15], block[s[6]],  block[s[7]]);
        G(v[0], v[5], v[10], v[15], block[s[8]],  block[s[9]]);
        G(v[1], v[6], v[11], v[12], block[s[10]], block[s[11]]);
        G(v[2], v[7], v[8],  v[13], block[s[12]], block[s[13]]);
        G(v[3], v[4], v[9],  v[14], block[s[14]], block[s[15]]);
    }

    for (int i = 0; i < 8; ++i) state[i] ^= v[i] ^ v[i + 8];
}

#undef HY2_ROTR64

// ---------------------------------------------------------------------------
// BLAKE2b Hasher
// ---------------------------------------------------------------------------
class BLAKE2b {
public:
    static constexpr size_t kOutputSize = 32;

    BLAKE2b() { Reset(); }

    void Reset() {
        for (int i = 0; i < 8; ++i) state_[i] = kBlake2bIV[i];
        state_[0] ^= 0x01010000 ^ kOutputSize;
        bufLen_ = 0;
        totalBytes_ = 0;
    }

    void Update(const void* data, size_t len) {
        auto* p = static_cast<const uint8_t*>(data);
        totalBytes_ += len;

        if (bufLen_ > 0) {
            size_t need = 128 - bufLen_;
            size_t take = (len < need) ? len : need;
            std::memcpy(buf_ + bufLen_, p, take);
            bufLen_ += take;
            p += take;
            len -= take;
            if (bufLen_ == 128) {
                Compress(state_, reinterpret_cast<const uint64_t*>(buf_), totalBytes_, false);
                bufLen_ = 0;
            }
        }

        while (len >= 128) {
            Compress(state_, reinterpret_cast<const uint64_t*>(p), totalBytes_ - len, false);
            p += 128;
            len -= 128;
        }

        if (len > 0) {
            std::memcpy(buf_, p, len);
            bufLen_ = len;
        }
    }

    void Final(void* out) {
        std::memset(buf_ + bufLen_, 0, 128 - bufLen_);
        Compress(state_, reinterpret_cast<const uint64_t*>(buf_), totalBytes_, true);
        uint8_t outBuf[64];
        for (int i = 0; i < 8; ++i) {
            std::memcpy(outBuf + i * 8, &state_[i], 8);
        }
        std::memcpy(out, outBuf, kOutputSize);
    }

    static void Hash(const void* data, size_t len, void* out) {
        BLAKE2b h;
        h.Update(data, len);
        h.Final(out);
    }

    static std::array<uint8_t, 32> Hash256(const void* data, size_t len) {
        std::array<uint8_t, 32> result;
        Hash(data, len, result.data());
        return result;
    }

private:
    uint64_t state_[8];
    uint8_t buf_[128];
    size_t bufLen_;
    uint64_t totalBytes_;
};

// ---------------------------------------------------------------------------
// XOR obfuscation (Salamander 专用)
// ---------------------------------------------------------------------------
inline void XorFast(uint8_t* out, const uint8_t* in, size_t len,
                    const uint8_t key[32]) {
    const uint64_t* key64 = reinterpret_cast<const uint64_t*>(key);
    uint64_t* out64 = reinterpret_cast<uint64_t*>(out);
    const uint64_t* in64 = reinterpret_cast<const uint64_t*>(in);
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        size_t ki = (i / 8) % 4;
        out64[i / 8] = in64[i / 8] ^ key64[ki];
    }
    for (; i < len; ++i) {
        out[i] = in[i] ^ key[i % 32];
    }
}

#if HY2_HAS_AVX2
inline void XorFastAVX2(uint8_t* out, const uint8_t* in, size_t len,
                         const uint8_t key[32]) {
    __m256i k0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(key));
    size_t i = 0;
    for (; i + 32 <= len; i += 32) {
        __m256i data = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(in + i));
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(out + i),
                            _mm256_xor_si256(data, k0));
    }
    for (; i < len; ++i) out[i] = in[i] ^ key[i % 32];
}
#endif

} // namespace hy2::perf

#undef HY2_HAS_AVX2
#undef HY2_HAS_SSE2
