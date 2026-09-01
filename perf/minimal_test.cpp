// minimal_test.cpp - 最小化编译测试
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <thread>
#include <mutex>
#include <deque>
#include <vector>
#include <atomic>
#include <unordered_map>
#include <memory>

// 测试1: TLS Pool
#include "tls_pool.hpp"
void test_pool() {
    std::printf("[1] TLS Pool...\n"); std::fflush(stdout);
    auto& pool = hy2::perf::FixedSizePool<1200>::Instance();
    auto s = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100000; ++i) { void* p = pool.Get(); pool.Put(p); }
    auto e = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(e - s).count() / 100000;
    std::printf("  FixedSizePool: %.1f ns/op\n", ns); std::fflush(stdout);
}

// 测试2: BLAKE2b
#include "blake2b_simd.hpp"
void test_blake() {
    std::printf("[2] BLAKE2b...\n"); std::fflush(stdout);
    uint8_t data[1200]; std::memset(data, 0xAB, 1200);
    uint8_t out[32];
    auto s = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; ++i) hy2::perf::BLAKE2b::Hash(data, 1200, out);
    auto e = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(e - s).count() / 10000;
    std::printf("  BLAKE2b 1200B: %.1f ns/op\n", ns); std::fflush(stdout);
}

// 测试3: SPSC Queue
#include "spsc_queue.hpp"
void test_spsc() {
    std::printf("[3] SPSC Queue...\n"); std::fflush(stdout);
    hy2::perf::SPSCQueue<uint64_t, 1024> q;
    auto s = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100000; ++i) { q.TryPush(i); q.TryPop(); }
    auto e = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(e - s).count() / 100000;
    std::printf("  SPSC Push+Pop: %.1f ns/op\n", ns); std::fflush(stdout);
}

// 测试4: CRTP
#include "static_polymorphism.hpp"
void test_crtp() {
    std::printf("[4] CRTP...\n"); std::fflush(stdout);
    alignas(64) uint8_t src[64], dst[1024];
    std::memset(src, 0xAB, 64);
    hy2::perf::MemoryWriter w(dst, sizeof(dst));
    auto s = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; ++i) { w.Write(src, 64); if (i % 16 == 0) w.Reset(); }
    auto e = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(e - s).count() / 1000000;
    std::printf("  CRTP Write: %.1f ns/op\n", ns); std::fflush(stdout);
}

// 测试5: RCU Map
#include "rcu.hpp"
void test_rcu() {
    std::printf("[5] RCU Map...\n"); std::fflush(stdout);
    hy2::perf::RCUMap<std::string, bool> cache;
    cache.Set("hello", true);
    auto s = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100000; ++i) { volatile auto v = cache.Get("hello"); (void)v; }
    auto e = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(e - s).count() / 100000;
    std::printf("  RCUMap Get: %.1f ns/op\n", ns); std::fflush(stdout);
}

int main() {
    std::printf("=== Minimal Performance Test ===\n"); std::fflush(stdout);
    test_pool();
    test_blake();
    test_spsc();
    test_crtp();
    test_rcu();
    std::printf("=== ALL DONE ===\n");
    return 0;
}
