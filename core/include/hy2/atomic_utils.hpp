// atomic_utils.hpp - Rewrite of core/internal/utils/atomic.go.
#pragma once

#include <atomic>
#include <chrono>
#include <mutex>

namespace hy2 {

// AtomicTime mirrors utils.AtomicTime (thread-safe time point).
class AtomicTime {
public:
    AtomicTime() : ns_(0) {}
    explicit AtomicTime(int64_t nanosSinceEpochSteady) : ns_(nanosSinceEpochSteady) {}

    static AtomicTime FromNow() {
        using namespace std::chrono;
        return AtomicTime(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
    }

    void Set(int64_t nanos) {
        ns_.store(nanos, std::memory_order_relaxed);
    }

    int64_t Get() const {
        return ns_.load(std::memory_order_relaxed);
    }

    bool OlderThan(int64_t nanos, int64_t timeoutNs) const {
        return nanos - Get() > timeoutNs;
    }

private:
    // Relaxed atomics, not a mutex: this is a best-effort activity timestamp
    // where no ordering between the timestamp and any other data is required,
    // and an aligned 64-bit load/store is atomic on every target. The mutex it
    // replaces was acquired twice per UDP datagram on the server's hot path
    // (server_udp.cpp Feed + receiveLoop).
    std::atomic<int64_t> ns_;
};

// Atomic<T> mirrors utils.Atomic[T] (mutex-backed, like atomic.Value).
template <typename T>
class Atomic {
public:
    Atomic() = default;
    explicit Atomic(T v) : v_(std::move(v)) {}

    T Load() const {
        std::lock_guard<std::mutex> lk(mu_);
        return v_;
    }

    void Store(T value) {
        std::lock_guard<std::mutex> lk(mu_);
        v_ = std::move(value);
    }

    T Swap(T newValue) {
        std::lock_guard<std::mutex> lk(mu_);
        T old = std::move(v_);
        v_ = std::move(newValue);
        return old;
    }

    bool CompareAndSwap(const T& expected, T newValue) requires std::equality_comparable<T> {
        std::lock_guard<std::mutex> lk(mu_);
        if (v_ == expected) {
            v_ = std::move(newValue);
            return true;
        }
        return false;
    }

private:
    mutable std::mutex mu_;
    T v_{};
};

} // namespace hy2
