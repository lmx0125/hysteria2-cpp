// alloc_bench.cpp - Microbenchmarks for memory allocation patterns.
// Tests allocation overhead in hot paths: buffer creation, string ops,
// vector resize, shared_ptr, etc.
#include "bench.hpp"

#include "hy2/common.hpp"
#include "hy2/protocol.hpp"

#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

using namespace hy2;
using namespace hy2::proto;

// ---------------------------------------------------------------------------
// Buffer allocation patterns
// ---------------------------------------------------------------------------

HY_BENCH(vector_alloc_1200B, 1200) {
    for (int i = 0; i < 100; ++i) {
        std::vector<uint8_t> buf(1200);
        (void)buf;
    }
}

HY_BENCH(vector_alloc_reuse_1200B, 1200) {
    std::vector<uint8_t> buf;
    for (int i = 0; i < 100; ++i) {
        buf.resize(1200);
        buf.resize(0);
    }
}

HY_BENCH(vector_reserve_1200B, 1200) {
    std::vector<uint8_t> buf;
    buf.reserve(1200);
    for (int i = 0; i < 100; ++i) {
        buf.resize(1200);
        (void)buf.data();
        buf.resize(0);
    }
}

// Stack vs heap for small buffers
HY_BENCH(array_1200B_on_stack, 1200) {
    for (int i = 0; i < 100; ++i) {
        uint8_t buf[1200];
        buf[0] = static_cast<uint8_t>(i);
        (void)buf;
    }
}

// shared_ptr allocation overhead
HY_BENCH(shared_ptr_make_1200B, 1200) {
    for (int i = 0; i < 100; ++i) {
        auto p = std::make_shared<std::vector<uint8_t>>(1200);
        (void)p;
    }
}

// unique_ptr allocation overhead
HY_BENCH(unique_ptr_make_1200B, 1200) {
    for (int i = 0; i < 100; ++i) {
        auto p = std::make_unique<std::vector<uint8_t>>(1200);
        (void)p;
    }
}

// malloc/free cycle
HY_BENCH(malloc_free_1200B, 1200) {
    for (int i = 0; i < 100; ++i) {
        void* p = std::malloc(1200);
        std::free(p);
    }
}

// memcpy overhead
HY_BENCH(memcpy_1200B, 1200) {
    uint8_t src[1200];
    uint8_t dst[1200];
    RandomBytes(src, 1200);
    for (int i = 0; i < 100; ++i) {
        std::memcpy(dst, src, 1200);
    }
}

// memmove overhead
HY_BENCH(memmove_1200B, 1200) {
    uint8_t buf[2400];
    RandomBytes(buf, 2400);
    for (int i = 0; i < 100; ++i) {
        std::memmove(buf + 100, buf, 1200);
    }
}

// ---------------------------------------------------------------------------
// String allocation patterns
// ---------------------------------------------------------------------------

HY_BENCH(string_create_short, 20) {
    for (int i = 0; i < 100; ++i) {
        std::string s("127.0.0.1:80");
        (void)s;
    }
}

HY_BENCH(string_create_medium, 50) {
    for (int i = 0; i < 100; ++i) {
        std::string s("very-long-subdomain.example.com:65535");
        (void)s;
    }
}

HY_BENCH(string_copy_short, 20) {
    std::string src("127.0.0.1:80");
    for (int i = 0; i < 100; ++i) {
        std::string dst = src;
        (void)dst;
    }
}

// ---------------------------------------------------------------------------
// Mutex overhead
// ---------------------------------------------------------------------------

namespace {
std::mutex g_mu;
}

HY_BENCH(mutex_lock_unlock, 0) {
    for (int i = 0; i < 1000; ++i) {
        g_mu.lock();
        g_mu.unlock();
    }
}

HY_BENCH(mutex_guard_construction, 0) {
    for (int i = 0; i < 1000; ++i) {
        std::lock_guard<std::mutex> lk(g_mu);
        (void)lk;
    }
}

// ---------------------------------------------------------------------------
// Atomic overhead
// ---------------------------------------------------------------------------

namespace {
std::atomic<int64_t> g_atomicCounter{0};
}

HY_BENCH(atomic_increment, 0) {
    for (int i = 0; i < 10000; ++i) {
        g_atomicCounter.fetch_add(1, std::memory_order_relaxed);
    }
}

HY_BENCH(atomic_load, 0) {
    for (int i = 0; i < 10000; ++i) {
        (void)g_atomicCounter.load(std::memory_order_relaxed);
    }
}

// ---------------------------------------------------------------------------
// Channel-like queue patterns
// ---------------------------------------------------------------------------

HY_BENCH(deque_push_pop_1200B, 1200) {
    std::deque<std::vector<uint8_t>> q;
    std::vector<uint8_t> item(1200);
    for (int i = 0; i < 100; ++i) {
        q.push_back(item);
        q.pop_front();
    }
}

HY_BENCH(vector_as_queue_1200B, 1200) {
    std::vector<std::vector<uint8_t>> q;
    q.reserve(256);
    std::vector<uint8_t> item(1200);
    for (int i = 0; i < 100; ++i) {
        q.push_back(item);
        q.erase(q.begin());
    }
}

// ---------------------------------------------------------------------------
// UDPMessage buffer reuse pattern (realistic packet processing)
// ---------------------------------------------------------------------------

HY_BENCH(packet_buffer_reuse_cycle, 1200) {
    std::vector<uint8_t> buf(1500);
    for (int i = 0; i < 100; ++i) {
        buf.resize(1500);
        RandomBytes(buf.data(), 1200);
        // Simulate: serialize UDPMessage into buf
        UDPMessage m;
        m.SessionID = 0x12345678;
        m.PacketID = static_cast<uint16_t>(i);
        m.FragID = 0;
        m.FragCount = 1;
        m.Addr = "127.0.0.1:53";
        m.Data.assign(buf.begin(), buf.begin() + 1200);
        (void)m.Serialize(buf.data(), buf.size());
        buf.resize(0);
    }
}
