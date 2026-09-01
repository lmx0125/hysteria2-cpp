// spsc_queue.hpp - 无锁 SPSC/MPMC RingBuffer (MSVC 兼容)
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <optional>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace hy2::perf {

// ---------------------------------------------------------------------------
// SPSCQueue<T, Capacity> - 固定容量无锁 SPSC 队列
// ---------------------------------------------------------------------------
template <typename T, size_t Capacity>
class SPSCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");

    struct CacheLinePad { char data_[64]; };
    static constexpr size_t kMask = Capacity - 1;

    CacheLinePad pad1_;
    std::atomic<size_t> write_pos_;
    CacheLinePad pad2_;
    std::atomic<size_t> read_pos_;
    CacheLinePad pad3_;
    alignas(64) uint8_t slots_[Capacity * sizeof(T)];

public:
    SPSCQueue() : write_pos_(0), read_pos_(0) {}

    bool TryPush(const T& value) {
        size_t w = write_pos_.load(std::memory_order_relaxed);
        size_t r = read_pos_.load(std::memory_order_acquire);
        if (w - r >= Capacity) return false;
        new (&slots_[w & kMask]) T(value);
        write_pos_.store(w + 1, std::memory_order_release);
        return true;
    }

    bool TryPush(T&& value) {
        size_t w = write_pos_.load(std::memory_order_relaxed);
        size_t r = read_pos_.load(std::memory_order_acquire);
        if (w - r >= Capacity) return false;
        new (&slots_[w & kMask]) T(static_cast<T&&>(value));
        write_pos_.store(w + 1, std::memory_order_release);
        return true;
    }

    void Push(const T& value) {
        while (!TryPush(value)) {
#ifdef _MSC_VER
            _mm_pause();
#elif defined(__x86_64__)
            __asm__ volatile("pause");
#endif
        }
    }

    std::optional<T> TryPop() {
        size_t r = read_pos_.load(std::memory_order_relaxed);
        size_t w = write_pos_.load(std::memory_order_acquire);
        if (r == w) return std::nullopt;
        T* ptr = reinterpret_cast<T*>(&slots_[r & kMask]);
        T value = static_cast<T&&>(*ptr);
        ptr->~T();
        read_pos_.store(r + 1, std::memory_order_release);
        return value;
    }

    bool TryPop(T& out) {
        size_t r = read_pos_.load(std::memory_order_relaxed);
        size_t w = write_pos_.load(std::memory_order_acquire);
        if (r == w) return false;
        T* ptr = reinterpret_cast<T*>(&slots_[r & kMask]);
        out = static_cast<T&&>(*ptr);
        ptr->~T();
        read_pos_.store(r + 1, std::memory_order_release);
        return true;
    }

    T Pop() {
        std::optional<T> val;
        while (!(val = TryPop())) {
#ifdef _MSC_VER
            _mm_pause();
#elif defined(__x86_64__)
            __asm__ volatile("pause");
#endif
        }
        return static_cast<T&&>(*val);
    }

    size_t SizeApprox() const {
        size_t w = write_pos_.load(std::memory_order_acquire);
        size_t r = read_pos_.load(std::memory_order_acquire);
        return w - r;
    }

    bool Empty() const { return SizeApprox() == 0; }
    bool Full() const { return SizeApprox() >= Capacity; }
    static constexpr size_t kCapacity = Capacity;
};

// ---------------------------------------------------------------------------
// MPMCQueue - Dmitry Vyukov MPMC bounded queue
// ---------------------------------------------------------------------------
template <typename T, size_t Capacity>
class MPMCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
    struct Cell { alignas(64) std::atomic<size_t> sequence; T data; };
    static constexpr size_t kMask = Capacity - 1;
    alignas(64) std::atomic<size_t> enqueue_pos_;
    alignas(64) std::atomic<size_t> dequeue_pos_;
    Cell cells_[Capacity];

public:
    MPMCQueue() : enqueue_pos_(0), dequeue_pos_(0) {
        for (size_t i = 0; i < Capacity; ++i)
            cells_[i].sequence.store(i, std::memory_order_relaxed);
    }

    bool TryPush(const T& value) {
        size_t pos = enqueue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            Cell& cell = cells_[pos & kMask];
            size_t seq = cell.sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos);
            if (diff == 0) {
                if (enqueue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    cell.data = value;
                    cell.sequence.store(pos + 1, std::memory_order_release);
                    return true;
                }
            } else if (diff < 0) {
                return false;
            } else {
                pos = enqueue_pos_.load(std::memory_order_relaxed);
            }
        }
    }

    bool TryPop(T& out) {
        size_t pos = dequeue_pos_.load(std::memory_order_relaxed);
        for (;;) {
            Cell& cell = cells_[pos & kMask];
            size_t seq = cell.sequence.load(std::memory_order_acquire);
            intptr_t diff = static_cast<intptr_t>(seq) - static_cast<intptr_t>(pos + 1);
            if (diff == 0) {
                if (dequeue_pos_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed)) {
                    out = static_cast<T&&>(cell.data);
                    cell.sequence.store(pos + Capacity, std::memory_order_release);
                    return true;
                }
            } else if (diff < 0) {
                return false;
            } else {
                pos = dequeue_pos_.load(std::memory_order_relaxed);
            }
        }
    }

    size_t SizeApprox() const {
        size_t e = enqueue_pos_.load(std::memory_order_acquire);
        size_t d = dequeue_pos_.load(std::memory_order_acquire);
        return (e > d) ? (e - d) : 0;
    }
};

} // namespace hy2::perf
