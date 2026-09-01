// test_pool.cpp - 单独测试 TLS 池
#include <cstdio>
#include <cstdint>
#include <chrono>
#include "tls_pool.hpp"

int main() {
    std::printf("Testing FixedSizePool...\n"); std::fflush(stdout);

    auto& pool = hy2::perf::FixedSizePool<1200>::Instance();
    std::printf("Pool created\n"); std::fflush(stdout);

    // Warmup
    for (int i = 0; i < 100; ++i) {
        void* p = pool.Get();
        pool.Put(p);
    }
    std::printf("Warmup done\n"); std::fflush(stdout);

    // Benchmark
    constexpr int N = 100000;
    auto s = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < N; ++i) {
        void* p = pool.Get();
        pool.Put(p);
    }
    auto e = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
    std::printf("FixedSizePool<1200> Get+Put: %.1f ns/op\n", ns);

    // malloc baseline
    {
        auto s2 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < N; ++i) {
            void* p = ::operator new(size_t{1200}, std::align_val_t{64});
            ::operator delete(p, std::align_val_t{64});
        }
        auto e2 = std::chrono::high_resolution_clock::now();
        double ns2 = std::chrono::duration<double, std::nano>(e2 - s2).count() / N;
        std::printf("malloc+free baseline:         %.1f ns/op\n", ns2);
    }

    std::printf("Pool test DONE\n");
    return 0;
}
