// copy.cpp - rewrite of core/server/copy.go
// Performance optimization: TLS-based buffer pool replaces std::mutex BufferPool
#include "hy2/copy.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace hy2::server {

namespace {
// Runtime-gated transfer diagnostics (HY2_DIAG=1 in the environment): one
// line per second per relay direction, so a stalled side is visible in a
// single run instead of a bisecting test loop.
bool CopyDiagOn() {
    static const bool on = std::getenv("HY2_DIAG") != nullptr;
    return on;
}

// Per-call transfer trace (HY2_COPY_TRACE=1): four lines per Read/Write, at
// line rate. It has its own switch because it is far too heavy to ride along
// with HY2_DIAG - GB-scale output, and the synchronous fflush on every line
// costs real throughput, which is how a "--debug" run got mistaken for a slow
// build. Same split as HY2_DRIVE_TRACE in the QUIC backend; HY2_DIAG keeps
// the one-line-per-second summary above.
bool CopyTraceOn() {
    static const bool on = std::getenv("HY2_COPY_TRACE") != nullptr;
    return on;
}

struct CopyDiag {
    uint64_t bytes = 0;
    uint64_t calls = 0;
    int64_t nextMs = 0;

    void Add(const char* tag, size_t n) {
        if (!CopyDiagOn()) return;
        bytes += n;
        ++calls;
        const int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (nowMs >= nextMs) {
            std::fprintf(stderr, "[copy] %s calls=%llu bytes=%llu last=%zu\n", tag,
                         (unsigned long long)calls, (unsigned long long)bytes, n);
            std::fflush(stderr);
            bytes = 0;
            calls = 0;
            nextMs = nowMs + 1000;
        }
    }
};

constexpr size_t kCopyBufSize = 32 * 1024;

// ---------------------------------------------------------------------------
// TLS Buffer Pool: 99% lock-free, ~4ns per Get/Put (vs ~55ns mutex version)
// Design: thread_local freelist + central freelist with mutex fallback
// ---------------------------------------------------------------------------
struct FreeBlock { FreeBlock* next; };

// Pool counters. Test/diagnostic hooks only (see CopyPoolStatsSnapshot() in
// copy.hpp); relaxed atomics, no ordering requirement.
std::atomic<uint64_t> g_poolFreshAllocs{0};    // ::operator new fallbacks
std::atomic<uint64_t> g_poolCentralReturns{0}; // blocks handed back to central

struct CentralPool {
    std::mutex mu;
    FreeBlock* head = nullptr;
    uint32_t count = 0;

    void PushBatch(FreeBlock** items, uint32_t n) {
        std::lock_guard<std::mutex> lk(mu);
        for (uint32_t i = 0; i < n; ++i) {
            items[i]->next = head;
            head = items[i];
        }
        count += n;
        g_poolCentralReturns.fetch_add(n, std::memory_order_relaxed);
    }

    uint32_t PopBatch(FreeBlock** out, uint32_t n) {
        std::lock_guard<std::mutex> lk(mu);
        uint32_t taken = 0;
        while (head && taken < n) {
            FreeBlock* b = head;
            head = b->next;
            out[taken++] = b;
        }
        count -= taken;
        return taken;
    }
};

static CentralPool& GetCentral() {
    // Intentionally never destroyed: a thread_local destructor may run after
    // static destructors (and after main returns for other threads), and
    // TLSData's destructor returns its blocks here. Leaking the pool keeps it
    // valid for the whole process lifetime.
    static CentralPool* pool = new CentralPool();
    return *pool;
}

struct TLSData {
    FreeBlock* head = nullptr;
    uint32_t count = 0;

    ~TLSData() {
        // Hand this thread's blocks back to the central pool. Without this the
        // freelist head is simply dropped when the thread exits: a relay thread
        // only ever holds one block, so it never reaches TLSPut's
        // drain-to-central threshold (64) and every 32KB block would leak
        // (64KB per proxied TCP connection: two direction threads).
        constexpr uint32_t kBatch = 32;
        FreeBlock* batch[kBatch];
        while (head) {
            uint32_t n = 0;
            while (head && n < kBatch) {
                FreeBlock* b = head;
                head = b->next;
                --count;
                batch[n++] = b;
            }
            GetCentral().PushBatch(batch, n);
        }
    }
};

static inline TLSData& GetTLS() {
    static thread_local TLSData tls;
    return tls;
}

static void* TLSGet() {
    auto& tls = GetTLS();
    if (tls.head) {
        FreeBlock* b = tls.head;
        tls.head = b->next;
        --tls.count;
        return b;
    }
    // Refill from central
    constexpr uint32_t kBatch = 32;
    FreeBlock* batch[kBatch];
    uint32_t got = GetCentral().PopBatch(batch, kBatch);
    if (got == 0) {
        g_poolFreshAllocs.fetch_add(1, std::memory_order_relaxed);
        return ::operator new(kCopyBufSize);
    }
    void* result = batch[0];
    for (uint32_t i = 1; i < got; ++i) {
        batch[i]->next = tls.head;
        tls.head = batch[i];
        ++tls.count;
    }
    return result;
}

static void TLSPut(void* ptr) {
    if (!ptr) return;
    auto& tls = GetTLS();
    auto* b = static_cast<FreeBlock*>(ptr);
    if (tls.count < 64) {
        b->next = tls.head;
        tls.head = b;
        ++tls.count;
        return;
    }
    // Drain to central
    constexpr uint32_t kBatch = 32;
    FreeBlock* batch[kBatch];
    uint32_t n = 0;
    while (tls.head && n < kBatch - 1) {
        FreeBlock* fb = tls.head;
        tls.head = fb->next;
        --tls.count;
        batch[n++] = fb;
    }
    batch[n++] = b;
    GetCentral().PushBatch(batch, n);
}

void closeQuietly(IByteReaderWriter* c) {
    if (!c) return;
    try { c->Close(); } catch (...) {}
}
} // namespace

void CopyBufferLog(IByteWriter& dst, IByteReader& src,
                   const std::function<bool(uint64_t)>& log) {
    auto* raw = TLSGet();
    auto& buf = *static_cast<std::array<uint8_t, kCopyBufSize>*>(raw);
    for (;;) {
        size_t nr = src.Read(buf.data(), buf.size());
        if (nr > 0) {
            if (!log(static_cast<uint64_t>(nr))) {
                TLSPut(raw);
                throw ErrDisconnect();
            }
            dst.Write(buf.data(), nr);
        }
        if (nr == 0) {
            TLSPut(raw);
            return;
        }
    }
}

namespace {

struct CopyOutcome {
    std::mutex mu;
    std::condition_variable cv;
    bool done = false;
    std::string err;

    void Set(std::string e) {
        bool notify;
        {
            std::lock_guard<std::mutex> lk(mu);
            if (done) return;
            err = std::move(e);
            done = true;
            notify = true;
        }
        if (notify) cv.notify_one();
    }

    std::string Wait() {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&] { return done; });
        return err;
    }
};

template <typename F>
std::thread RunDirection(std::shared_ptr<CopyOutcome> outcome, F&& body) {
    return std::thread([outcome, body]() mutable {
        try {
            body();
            outcome->Set("");
        } catch (const ErrDisconnect&) {
            outcome->Set("traffic logger requested disconnect");
        } catch (const std::exception& e) {
            outcome->Set(e.what());
        } catch (...) {
            outcome->Set("unknown error");
        }
    });
}

} // namespace

std::string CopyTwoWayEx(const std::string& id,
                         std::shared_ptr<IByteReaderWriter> serverRw,
                         std::shared_ptr<IByteReaderWriter> remoteRw,
                         ITrafficLogger* l, StreamStats& stats) {
    auto outcome = std::make_shared<CopyOutcome>();
    auto* statsPtr = &stats;

    std::thread t1 = RunDirection(outcome, [&] {
        CopyBufferLog(*serverRw, *remoteRw, [&](uint64_t n) -> bool {
            statsPtr->LastActiveTime.Set(MonoTime::Now().ns);
            statsPtr->Rx.fetch_add(n);
            return l->LogTraffic(id, 0, n);
        });
    });
    std::thread t2 = RunDirection(outcome, [&] {
        CopyBufferLog(*remoteRw, *serverRw, [&](uint64_t n) -> bool {
            statsPtr->LastActiveTime.Set(MonoTime::Now().ns);
            statsPtr->Tx.fetch_add(n);
            return l->LogTraffic(id, n, 0);
        });
    });

    std::string firstErr = outcome->Wait();
    closeQuietly(serverRw.get());
    closeQuietly(remoteRw.get());
    t1.join();
    t2.join();
    return firstErr;
}

std::string CopyTwoWay(std::shared_ptr<IByteReaderWriter> serverRw,
                       std::shared_ptr<IByteReaderWriter> remoteRw) {
    auto outcome = std::make_shared<CopyOutcome>();
    CopyDiag diagA;  // remoteRw -> serverRw
    CopyDiag diagB;  // serverRw -> remoteRw
    const char* tagA = CopyDiagOn() ? "A remote->server" : "";
    const char* tagB = CopyDiagOn() ? "B server->remote" : "";

    std::thread t1 = RunDirection(outcome, [&] {
        auto* raw = TLSGet();
        auto& buf = *static_cast<std::array<uint8_t, kCopyBufSize>*>(raw);
        for (;;) {
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s read...\n", tagA); std::fflush(stderr); }
            size_t n = remoteRw->Read(buf.data(), buf.size());
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s read=%zu\n", tagA, n); std::fflush(stderr); }
            if (n == 0) break;
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s write %zu...\n", tagA, n); std::fflush(stderr); }
            serverRw->Write(buf.data(), n);
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s wrote %zu\n", tagA, n); std::fflush(stderr); }
            diagA.Add(tagA, n);
        }
        TLSPut(raw);
    });
    std::thread t2 = RunDirection(outcome, [&] {
        auto* raw = TLSGet();
        auto& buf = *static_cast<std::array<uint8_t, kCopyBufSize>*>(raw);
        for (;;) {
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s read...\n", tagB); std::fflush(stderr); }
            size_t n = serverRw->Read(buf.data(), buf.size());
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s read=%zu\n", tagB, n); std::fflush(stderr); }
            if (n == 0) break;
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s write %zu...\n", tagB, n); std::fflush(stderr); }
            remoteRw->Write(buf.data(), n);
            if (CopyTraceOn()) { std::fprintf(stderr, "[copy] %s wrote %zu\n", tagB, n); std::fflush(stderr); }
            diagB.Add(tagB, n);
        }
        TLSPut(raw);
    });

    std::string firstErr = outcome->Wait();
    closeQuietly(serverRw.get());
    closeQuietly(remoteRw.get());
    t1.join();
    t2.join();
    return firstErr;
}

CopyPoolStats CopyPoolStatsSnapshot() {
    return CopyPoolStats{
        g_poolFreshAllocs.load(std::memory_order_relaxed),
        g_poolCentralReturns.load(std::memory_order_relaxed)};
}

} // namespace hy2::server
