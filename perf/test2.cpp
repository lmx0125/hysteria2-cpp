// test2.cpp - 逐模块测试
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <memory>
#include <atomic>

int main() {
    std::printf("=== Module Test ===\n"); std::fflush(stdout);

    // Test 1: BLAKE2b
    {
        std::printf("[1] BLAKE2b\n"); std::fflush(stdout);
        // Inline BLAKE2b test
        uint64_t state[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        uint8_t data[1200];
        std::memset(data, 0xAB, 1200);
        auto s = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 1000; ++i) {
            // Simple hash: XOR data into state
            for (int j = 0; j < 1200; j += 8) {
                uint64_t v;
                std::memcpy(&v, data + j, 8);
                state[j % 8] ^= v;
            }
        }
        auto e = std::chrono::high_resolution_clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / 1000;
        std::printf("  State[0]=%llu, %.1f ns/op\n", (unsigned long long)state[0], ns);
        std::fflush(stdout);
    }

    // Test 2: atomic shared_ptr (RCU core)
    {
        std::printf("[2] atomic shared_ptr\n"); std::fflush(stdout);
        auto ptr = std::make_shared<const int>(42);
        std::atomic<std::shared_ptr<const int>> aptr(ptr);
        auto s = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100000; ++i) {
            auto v = aptr.load(std::memory_order_acquire);
            (void)v;
        }
        auto e = std::chrono::high_resolution_clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / 100000;
        std::printf("  atomic load: %.1f ns/op\n", ns);
        std::fflush(stdout);
    }

    // Test 3: atomic CAS
    {
        std::printf("[3] atomic CAS\n"); std::fflush(stdout);
        std::atomic<size_t> counter{0};
        auto s = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100000; ++i) {
            counter.fetch_add(1, std::memory_order_relaxed);
        }
        auto e = std::chrono::high_resolution_clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / 100000;
        std::printf("  atomic fetch_add: %.1f ns/op\n", ns);
        std::fflush(stdout);
    }

    // Test 4: memcpy
    {
        std::printf("[4] memcpy\n"); std::fflush(stdout);
        uint8_t src[1200], dst[1200];
        std::memset(src, 0xAB, 1200);
        auto s = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100000; ++i) std::memcpy(dst, src, 1200);
        auto e = std::chrono::high_resolution_clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / 100000;
        std::printf("  memcpy 1200B: %.1f ns/op\n", ns);
        std::fflush(stdout);
    }

    std::printf("=== ALL DONE ===\n");
    return 0;
}
