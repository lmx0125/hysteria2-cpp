// blake2b_bench.cpp - BLAKE2b comparison benchmark.
// Compares: current pure-C++ BLAKE2b-256 vs OpenSSL EVP_blake2b512.
// Note: OpenSSL 4.0.1 has blake2b512 but not blake2b256.
// We benchmark both to compare raw throughput of the BLAKE2b compression core.
#include "bench.hpp"

#include "hy2/common.hpp"
#include "hy2/obfs/blake2b.hpp"

#include <cstring>
#include <vector>

#if HY2_BENCH_HAS_OPENSSL
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#endif

using namespace hy2;
using namespace hy2::crypto;

// ============================================================================
// Helpers
// ============================================================================

namespace {
std::vector<uint8_t> MakePayload(size_t len) {
    std::vector<uint8_t> buf(len);
    RandomBytes(buf.data(), len);
    return buf;
}
} // namespace

// ============================================================================
// A. Current pure-C++ BLAKE2b-256
// ============================================================================

HY_BENCH(blake2b_cpp_32B, 32) {
    auto p = MakePayload(32);
    for (int i = 0; i < 1000; ++i) {
        (void)Blake2bSum256(p.data(), p.size());
    }
}

HY_BENCH(blake2b_cpp_64B, 64) {
    auto p = MakePayload(64);
    for (int i = 0; i < 1000; ++i) {
        (void)Blake2bSum256(p.data(), p.size());
    }
}

HY_BENCH(blake2b_cpp_1200B, 1200) {
    auto p = MakePayload(1200);
    for (int i = 0; i < 1000; ++i) {
        (void)Blake2bSum256(p.data(), p.size());
    }
}

// Salamander pattern: hash 40-byte PSK||salt per packet
HY_BENCH(blake2b_cpp_salamander_40B, 40) {
    auto p = MakePayload(40);
    for (int i = 0; i < 1000; ++i) {
        (void)Blake2bSum256(p.data(), 40);
    }
}

// ============================================================================
// B. OpenSSL EVP_blake2b512 (one-shot)
// ============================================================================

#if HY2_BENCH_HAS_OPENSSL

HY_BENCH(blake2b_openssl_oneshot_32B, 32) {
    auto p = MakePayload(32);
    for (int i = 0; i < 1000; ++i) {
        unsigned int mdLen = 0;
        uint8_t out[64];
        EVP_Digest(p.data(), p.size(), out, &mdLen, EVP_blake2b512(), nullptr);
    }
}

HY_BENCH(blake2b_openssl_oneshot_64B, 64) {
    auto p = MakePayload(64);
    for (int i = 0; i < 1000; ++i) {
        unsigned int mdLen = 0;
        uint8_t out[64];
        EVP_Digest(p.data(), p.size(), out, &mdLen, EVP_blake2b512(), nullptr);
    }
}

HY_BENCH(blake2b_openssl_oneshot_1200B, 1200) {
    auto p = MakePayload(1200);
    for (int i = 0; i < 1000; ++i) {
        unsigned int mdLen = 0;
        uint8_t out[64];
        EVP_Digest(p.data(), p.size(), out, &mdLen, EVP_blake2b512(), nullptr);
    }
}

HY_BENCH(blake2b_openssl_oneshot_salamander_40B, 40) {
    auto p = MakePayload(40);
    for (int i = 0; i < 1000; ++i) {
        unsigned int mdLen = 0;
        uint8_t out[64];
        EVP_Digest(p.data(), 40, out, &mdLen, EVP_blake2b512(), nullptr);
    }
}

// ============================================================================
// C. OpenSSL EVP context (persistent, init+update+final per call)
// ============================================================================

HY_BENCH(blake2b_openssl_ctx_32B, 32) {
    auto p = MakePayload(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    for (int i = 0; i < 1000; ++i) {
        EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr);
        EVP_DigestUpdate(ctx, p.data(), p.size());
        uint8_t out[64];
        unsigned int mdLen = 0;
        EVP_DigestFinal_ex(ctx, out, &mdLen);
    }
    EVP_MD_CTX_free(ctx);
}

HY_BENCH(blake2b_openssl_ctx_1200B, 1200) {
    auto p = MakePayload(1200);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    for (int i = 0; i < 1000; ++i) {
        EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr);
        EVP_DigestUpdate(ctx, p.data(), p.size());
        uint8_t out[64];
        unsigned int mdLen = 0;
        EVP_DigestFinal_ex(ctx, out, &mdLen);
    }
    EVP_MD_CTX_free(ctx);
}

HY_BENCH(blake2b_openssl_ctx_salamander_40B, 40) {
    auto p = MakePayload(40);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    for (int i = 0; i < 1000; ++i) {
        EVP_DigestInit_ex(ctx, EVP_blake2b512(), nullptr);
        EVP_DigestUpdate(ctx, p.data(), 40);
        uint8_t out[64];
        unsigned int mdLen = 0;
        EVP_DigestFinal_ex(ctx, out, &mdLen);
    }
    EVP_MD_CTX_free(ctx);
}

#else // !HY2_BENCH_HAS_OPENSSL

HY_BENCH_NOSize(blake2b_openssl_unavailable) {
    std::printf("  (OpenSSL not available - EVP benchmarks skipped)\n");
}

#endif // HY2_BENCH_HAS_OPENSSL
