// tls_pool.hpp - Thread-Local 极速无锁内存池 (MSVC 兼容)
#pragma once

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace hy2::perf {

inline constexpr size_t kMaxPoolSize = 4096;
inline constexpr size_t kNumSizeClasses = 7;

inline constexpr size_t RoundUpPow2(size_t v) {
    v--; v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16; v |= v >> 32;
    return v + 1;
}

inline size_t SizeClassIndex(size_t bytes) {
    if (bytes == 0) return 0;
    size_t aligned = RoundUpPow2(bytes);
    if (aligned <= 64) return 0;
    if (aligned >= kMaxPoolSize) return kNumSizeClasses - 1;
#ifdef _MSC_VER
    unsigned long idx;
    _BitScanReverse64(&idx, aligned);
    return static_cast<size_t>(idx - 6);
#else
    return static_cast<size_t>(63 - __builtin_clzll(aligned) - 6);
#endif
}

inline size_t SizeClassBytes(size_t idx) {
    return size_t{1} << (idx + 6);
}

struct FreeBlock { FreeBlock* next; };

// ---------------------------------------------------------------------------
// CentralFreeList (mutex 保护, 跨线程共享)
// ---------------------------------------------------------------------------
class CentralFreeList {
    CentralFreeList(const CentralFreeList&) = delete;
    CentralFreeList& operator=(const CentralFreeList&) = delete;
public:
    CentralFreeList() : head_(nullptr), count_(0) {}

    size_t PopBatch(void** out, size_t n) {
        std::lock_guard<std::mutex> lk(mu_);
        size_t taken = 0;
        while (head_ && taken < n) {
            FreeBlock* b = head_;
            head_ = b->next;
            out[taken++] = b;
        }
        count_ -= taken;
        return taken;
    }

    void PushBatch(void** items, size_t n) {
        std::lock_guard<std::mutex> lk(mu_);
        for (size_t i = 0; i < n; ++i) {
            auto* b = static_cast<FreeBlock*>(items[i]);
            b->next = head_;
            head_ = b;
        }
        count_ += n;
    }

    size_t Count() const { return count_; }

private:
    FreeBlock* head_;
    size_t count_;
    std::mutex mu_;
};

// 全局 CentralFreeList 数组
inline CentralFreeList& GetCentral(size_t idx) {
    static CentralFreeList lists[kNumSizeClasses];
    return lists[idx];
}

// ---------------------------------------------------------------------------
// FixedSizePool<BlockSize> - 固定大小 TLS 内存池
// ---------------------------------------------------------------------------
template <size_t BlockSize>
class FixedSizePool {
    static_assert(BlockSize >= sizeof(FreeBlock*), "Block too small");
    static_assert(BlockSize <= kMaxPoolSize, "Block too large");

    static constexpr size_t kTlsCapacity = 64;
    static constexpr size_t kBatchSize = 32;

    struct alignas(64) TlsData {
        FreeBlock* head = nullptr;
        size_t count = 0;
    };

    static TlsData& GetTls() {
        static thread_local TlsData tls;
        return tls;
    }

    void* Refill() {
        void* batch[kBatchSize];
        size_t got = GetCentral(0).PopBatch(batch, kBatchSize);
        if (got == 0) {
            return ::operator new(BlockSize);
        }
        auto& tls = GetTls();
        void* result = batch[0];
        for (size_t i = 1; i < got; ++i) {
            auto* b = static_cast<FreeBlock*>(batch[i]);
            b->next = tls.head;
            tls.head = b;
            ++tls.count;
        }
        return result;
    }

    void Drain(void* extra) {
        void* batch[kBatchSize];
        size_t n = 0;
        auto& tls = GetTls();
        while (tls.head && n < kBatchSize - 1) {
            FreeBlock* b = tls.head;
            tls.head = b->next;
            --tls.count;
            batch[n++] = b;
        }
        batch[n++] = extra;
        GetCentral(0).PushBatch(batch, n);
    }

public:
    FixedSizePool() = default;
    FixedSizePool(const FixedSizePool&) = delete;
    FixedSizePool& operator=(const FixedSizePool&) = delete;

    static FixedSizePool& Instance() {
        static FixedSizePool pool;
        return pool;
    }

    void* Get() {
        auto& tls = GetTls();
        if (tls.head) {
            FreeBlock* b = tls.head;
            tls.head = b->next;
            --tls.count;
            return b;
        }
        return Refill();
    }

    void Put(void* ptr) {
        if (!ptr) return;
        auto& tls = GetTls();
        auto* b = static_cast<FreeBlock*>(ptr);
        if (tls.count < kTlsCapacity) {
            b->next = tls.head;
            tls.head = b;
            ++tls.count;
            return;
        }
        Drain(ptr);
    }
};

// ---------------------------------------------------------------------------
// TlsPool<T> - 类型化 TLS 池
// ---------------------------------------------------------------------------
template <typename T>
class TlsPool {
    static_assert(sizeof(T) <= kMaxPoolSize, "Type too large");

    struct alignas(64) TlsData {
        FreeBlock* heads[kNumSizeClasses] = {};
        size_t counts[kNumSizeClasses] = {};
    };

    static TlsData& GetTls() {
        static thread_local TlsData tls;
        return tls;
    }

    static void* GetRaw(size_t bytes) {
        if (bytes > kMaxPoolSize) return ::operator new(bytes);
        size_t ci = SizeClassIndex(bytes);
        auto& tls = GetTls();
        if (tls.heads[ci]) {
            FreeBlock* b = tls.heads[ci];
            tls.heads[ci] = b->next;
            --tls.counts[ci];
            return b;
        }
        size_t bs = SizeClassBytes(ci);
        void* batch[16];
        size_t got = GetCentral(ci).PopBatch(batch, 16);
        if (got == 0) return ::operator new(bs);
        void* result = batch[0];
        for (size_t i = 1; i < got; ++i) {
            auto* b = static_cast<FreeBlock*>(batch[i]);
            b->next = tls.heads[ci];
            tls.heads[ci] = b;
            ++tls.counts[ci];
        }
        return result;
    }

    static void PutRaw(void* ptr, size_t bytes) {
        if (!ptr) return;
        if (bytes > kMaxPoolSize) { ::operator delete(ptr); return; }
        size_t ci = SizeClassIndex(bytes);
        auto& tls = GetTls();
        auto* b = static_cast<FreeBlock*>(ptr);
        if (tls.counts[ci] < 32) {
            b->next = tls.heads[ci]; tls.heads[ci] = b; ++tls.counts[ci]; return;
        }
        void* batch[16]; size_t n = 0;
        while (tls.heads[ci] && n < 15) {
            FreeBlock* fb = tls.heads[ci]; tls.heads[ci] = fb->next; --tls.counts[ci]; batch[n++] = fb;
        }
        batch[n++] = ptr;
        GetCentral(ci).PushBatch(batch, n);
    }

public:
    TlsPool() = default;
    T* Get() { return static_cast<T*>(GetRaw(sizeof(T))); }
    void Put(T* ptr) { PutRaw(ptr, sizeof(T)); }
};

using CopyBufferPool = FixedSizePool<32 * 1024>;
using PktBufPool = FixedSizePool<1500>;

} // namespace hy2::perf
