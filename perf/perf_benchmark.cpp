// perf_benchmark.cpp - 单线程性能基准测试 (MSVC 兼容)
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <numeric>
#include <thread>
#include <unordered_map>
#include <vector>

#include "tls_pool.hpp"
#include "blake2b_simd.hpp"
#include "spsc_queue.hpp"
#include "static_polymorphism.hpp"
#include "rcu.hpp"

using namespace hy2::perf;
using Clock = std::chrono::high_resolution_clock;

// ===================================================================
// 1. TLS Pool vs mutex
// ===================================================================
void BenchTlsPool() {
    std::printf("\n=== 1. TLS Pool vs std::mutex ===\n");
    constexpr size_t kB = 1200;
    constexpr size_t N = 200000;

    {
        std::mutex mu;
        std::vector<void*> pool;
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) {
            void* p = nullptr;
            { std::lock_guard<std::mutex> lk(mu); if (!pool.empty()) { p = pool.back(); pool.pop_back(); } }
            if (!p) p = ::operator new(kB, std::align_val_t{64});
            { std::lock_guard<std::mutex> lk(mu); pool.push_back(p); }
        }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "std::mutex Get+Put", ns);
    }
    {
        auto& pool = FixedSizePool<1200>::Instance();
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) {
            void* p = pool.Get();
            pool.Put(p);
        }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "FixedSizePool Get+Put", ns);
    }
    {
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) {
            void* p = ::operator new(kB, std::align_val_t{64});
            ::operator delete(p, std::align_val_t{64});
        }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "malloc+free (baseline)", ns);
    }
}

// ===================================================================
// 2. BLAKE2b
// ===================================================================
void BenchBlake2b() {
    std::printf("\n=== 2. BLAKE2b Performance ===\n");
    constexpr size_t N = 20000;

    for (size_t sz : {64, 256, 1200}) {
        std::vector<uint8_t> input(sz);
        std::iota(input.begin(), input.end(), 0);
        uint8_t out[32];
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) BLAKE2b::Hash(input.data(), input.size(), out);
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  BLAKE2b %3zuB              %8.1f ns/op\n", sz, ns);
    }

    std::printf("\n--- XOR Obfuscation ---\n");
    {
        uint8_t key[32]; std::memset(key, 0xAB, 32);
        std::vector<uint8_t> in(1200, 0xCD), out(1200);
        constexpr size_t XN = 100000;
        auto s = Clock::now();
        for (size_t i = 0; i < XN; ++i) XorFast(out.data(), in.data(), 1200, key);
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / XN;
        std::printf("  XorFast 1200B             %8.1f ns/op\n", ns);
    }
}

// ===================================================================
// 3. SPSC Queue (single-threaded push/pop)
// ===================================================================
void BenchSPSC() {
    std::printf("\n=== 3. SPSC Queue (single-thread) ===\n");
    constexpr size_t N = 200000;

    {
        SPSCQueue<uint64_t, 1024> q;
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) q.TryPush(i);
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "SPSC Push (warm cache)", ns);
    }
    {
        SPSCQueue<uint64_t, 1024> q;
        for (size_t i = 0; i < N; ++i) q.TryPush(i);
        uint64_t dummy = 0;
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) { auto v = q.TryPop(); dummy += *v; }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "SPSC Pop (warm cache)", ns);
    }
    {
        SPSCQueue<uint64_t, 1024> q;
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) { q.TryPush(i); q.TryPop(); }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "SPSC Push+Pop (roundtrip)", ns);
    }
    {
        std::mutex mu;
        std::deque<uint64_t> q;
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) {
            { std::lock_guard<std::mutex> lk(mu); q.push_back(i); }
            { std::lock_guard<std::mutex> lk(mu); q.pop_front(); }
        }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "mutex+deque Push+Pop (baseline)", ns);
    }
}

// ===================================================================
// 4. CRTP vs 虚函数
// ===================================================================
class VirtualWriter {
public:
    virtual ~VirtualWriter() = default;
    virtual void Write(const uint8_t* p, size_t n) = 0;
    virtual void Reset() = 0;
};
class MemWriterVirt : public VirtualWriter {
    uint8_t* buf_; size_t cap_, pos_;
public:
    MemWriterVirt(uint8_t* b, size_t c) : buf_(b), cap_(c), pos_(0) {}
    void Write(const uint8_t* p, size_t n) override { std::memcpy(buf_+pos_, p, n); pos_+=n; }
    void Reset() override { pos_ = 0; }
};

void BenchCRTP() {
    std::printf("\n=== 4. CRTP vs 虚函数 ===\n");
    constexpr size_t N = 5000000;
    constexpr size_t WS = 64;
    alignas(64) uint8_t src[WS], dst[WS*16];
    std::memset(src, 0xAB, WS);

    {
        VirtualWriter* w = new MemWriterVirt(dst, sizeof(dst));
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) { w->Write(src, WS); if (i % 16 == 0) w->Reset(); }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "VirtualWriter::Write", ns);
        delete w;
    }
    {
        MemoryWriter w(dst, sizeof(dst));
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) { w.Write(src, WS); if (i % 16 == 0) w.Reset(); }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "CRTP MemoryWriter::Write", ns);
    }
    {
        size_t pos = 0;
        auto s = Clock::now();
        for (size_t i = 0; i < N; ++i) { std::memcpy(dst+pos, src, WS); pos+=WS; if (pos > sizeof(dst)-WS) pos=0; }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / N;
        std::printf("  %-40s %8.1f ns/op\n", "memcpy (baseline)", ns);
    }
}

// ===================================================================
// 5. RCU Map vs mutex map
// ===================================================================
void BenchRCUMap() {
    std::printf("\n=== 5. RCU Map vs mutex map ===\n");
    constexpr size_t E = 100, W = 1000, R = 50000;

    std::vector<std::string> keys(E);
    for (size_t i = 0; i < E; ++i) keys[i] = "k" + std::to_string(i);

    // Mutex map: write-heavy
    {
        std::mutex mu; std::unordered_map<std::string,bool> cache;
        for (auto& k:keys) cache[k]=true;
        auto s = Clock::now();
        for (size_t w = 0; w < W; ++w) {
            std::lock_guard<std::mutex> lk(mu);
            cache[keys[w % E]] = (w % 2 == 0);
        }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / W;
        std::printf("  %-40s %8.1f ns/op (write)\n", "mutex map Set", ns);
    }
    // RCU map: write-heavy
    {
        RCUMap<std::string,bool> cache;
        for (auto& k:keys) cache.Set(k,true);
        auto s = Clock::now();
        for (size_t w = 0; w < W; ++w) cache.Set(keys[w % E], (w % 2 == 0));
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / W;
        std::printf("  %-40s %8.1f ns/op (write)\n", "RCUMap Set", ns);
    }
    // Mutex map: read-heavy
    {
        std::mutex mu; std::unordered_map<std::string,bool> cache;
        for (auto& k:keys) cache[k]=true;
        auto s = Clock::now();
        for (size_t r = 0; r < R; ++r) {
            std::lock_guard<std::mutex> lk(mu);
            volatile bool v = cache[keys[r % E]]; (void)v;
        }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / R;
        std::printf("  %-40s %8.1f ns/op (read)\n", "mutex map Get", ns);
    }
    // RCU map: read-heavy
    {
        RCUMap<std::string,bool> cache;
        for (auto& k:keys) cache.Set(k,true);
        auto s = Clock::now();
        for (size_t r = 0; r < R; ++r) { volatile auto v = cache.Get(keys[r % E]); (void)v; }
        auto e = Clock::now();
        double ns = std::chrono::duration<double, std::nano>(e - s).count() / R;
        std::printf("  %-40s %8.1f ns/op (read)\n", "RCUMap Get", ns);
    }
}

// ===================================================================
int main() {
    std::printf("==============================================\n");
    std::printf("  HY2-C++ Performance Benchmark\n");
#if defined(_MSC_VER)
    std::printf("  Compiler: MSVC %d\n", _MSC_VER);
#endif
    std::printf("  Date:     %s %s\n", __DATE__, __TIME__);
    std::printf("==============================================\n");
    std::fflush(stdout);

    BenchTlsPool(); std::fflush(stdout);
    BenchBlake2b(); std::fflush(stdout);
    BenchSPSC();    std::fflush(stdout);
    BenchCRTP();    std::fflush(stdout);
    BenchRCUMap();  std::fflush(stdout);

    std::printf("\n==============================================\n");
    std::printf("  Done!\n");
    std::printf("==============================================\n");
    return 0;
}
