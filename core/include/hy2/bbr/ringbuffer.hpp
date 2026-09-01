// ringbuffer.hpp - rewrite of core/internal/congestion/bbr/ringbuffer.go.
#pragma once

#include <cstddef>
#include <stdexcept>
#include <utility>
#include <vector>

namespace hy2::bbr {

// RingBuffer is a ring buffer. It acts as a heap that doesn't cause any
// allocations after Init.
template <typename T>
class RingBuffer {
public:
    // Preallocates a buffer with a certain size.
    void Init(std::size_t size) { ring_.assign(size, T{}); }

    std::size_t Len() const {
        if (full_) {
            return ring_.size();
        }
        if (tailPos_ >= headPos_) {
            return tailPos_ - headPos_;
        }
        return tailPos_ - headPos_ + ring_.size();
    }

    bool Empty() const { return !full_ && headPos_ == tailPos_; }

    // PushBack adds a new element. If the buffer is full, its capacity is
    // increased first.
    void PushBack(T t) {
        if (full_ || ring_.empty()) {
            Grow();
        }
        ring_[tailPos_] = std::move(t);
        tailPos_++;
        if (tailPos_ == ring_.size()) {
            tailPos_ = 0;
        }
        if (tailPos_ == headPos_) {
            full_ = true;
        }
    }

    // PopFront returns the next element. Must not be called when empty.
    T PopFront() {
        if (Empty()) {
            throw std::logic_error("bbr/ringbuffer: pop from an empty queue");
        }
        full_ = false;
        T t = std::move(ring_[headPos_]);
        ring_[headPos_] = T{};
        headPos_++;
        if (headPos_ == ring_.size()) {
            headPos_ = 0;
        }
        return t;
    }

    // Offset returns the offset element. Must not be called when empty or with
    // an index larger than Len().
    T* Offset(std::size_t index) {
        if (Empty() || index >= Len()) {
            throw std::logic_error("bbr/ringbuffer: offset from invalid index");
        }
        std::size_t offset = (headPos_ + index) % ring_.size();
        return &ring_[offset];
    }
    const T* Offset(std::size_t index) const {
        if (Empty() || index >= Len()) {
            throw std::logic_error("bbr/ringbuffer: offset from invalid index");
        }
        std::size_t offset = (headPos_ + index) % ring_.size();
        return &ring_[offset];
    }

    T* Front() {
        if (Empty()) {
            throw std::logic_error("bbr/ringbuffer: front from an empty queue");
        }
        return &ring_[headPos_];
    }
    const T* Front() const {
        if (Empty()) {
            throw std::logic_error("bbr/ringbuffer: front from an empty queue");
        }
        return &ring_[headPos_];
    }

    T* Back() { return Offset(Len() - 1); }
    const T* Back() const { return Offset(Len() - 1); }

    // Clear removes all elements.
    void Clear() {
        for (auto& e : ring_) {
            e = T{};
        }
        headPos_ = 0;
        tailPos_ = 0;
        full_ = false;
    }

private:
    // Grows the maximum size of the queue. Assumes the queue is full (or empty).
    void Grow() {
        std::vector<T> oldRing;
        oldRing.swap(ring_);
        std::size_t oldSize = oldRing.size();
        std::size_t newSize = oldSize * 2;
        if (newSize == 0) {
            newSize = 1;
        }
        ring_.assign(newSize, T{});
        std::size_t headLen = 0;
        for (std::size_t i = headPos_; i < oldSize; i++) {
            ring_[headLen++] = std::move(oldRing[i]);
        }
        for (std::size_t i = 0; i < headPos_; i++) {
            ring_[headLen++] = std::move(oldRing[i]);
        }
        headPos_ = 0;
        tailPos_ = oldSize;
        full_ = false;
    }

    std::vector<T> ring_;
    std::size_t headPos_ = 0;
    std::size_t tailPos_ = 0;
    bool full_ = false;
};

} // namespace hy2::bbr
