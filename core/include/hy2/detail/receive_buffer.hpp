#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>

namespace hy2::detail {

// Byte FIFO for the stream receive path. The owner provides synchronization.
// Storage tracks peak unread bytes, not cumulative traffic. Once warmed up,
// appending and reading only copy the new/consumed bytes (no compaction).
class ReceiveBuffer {
public:
    size_t size() const noexcept { return size_; }
    size_t capacity() const noexcept { return capacity_; }
    void clear() noexcept { head_ = 0; size_ = 0; }

    void Append(const uint8_t* data, size_t len) {
        if (len == 0) return;
        if (len > std::numeric_limits<size_t>::max() - size_) {
            throw std::length_error("receive buffer overflow");
        }
        const size_t required = size_ + len;
        if (required > capacity_) Grow(required);
        const size_t tail = Advance(head_, size_);
        const size_t first = std::min(len, capacity_ - tail);
        std::memcpy(data_.get() + tail, data, first);
        if (len > first) std::memcpy(data_.get(), data + first, len - first);
        size_ += len;
    }

    size_t Read(uint8_t* out, size_t len) {
        const size_t take = std::min(len, size_);
        if (take == 0) return 0;
        CopyFront(out, take);
        head_ = Advance(head_, take);
        size_ -= take;
        if (size_ == 0) head_ = 0;
        return take;
    }

private:
    // Avoid modulo in the hot path and overflow in head + offset.
    size_t Advance(size_t head, size_t offset) const noexcept {
        const size_t remaining = capacity_ - head;
        return offset >= remaining ? offset - remaining : head + offset;
    }

    void CopyFront(uint8_t* out, size_t len) const {
        const size_t first = std::min(len, capacity_ - head_);
        if (first > 0) std::memcpy(out, data_.get() + head_, first);
        if (len > first) std::memcpy(out + first, data_.get(), len - first);
    }

    void Grow(size_t required) {
        const size_t doubled = capacity_ <= std::numeric_limits<size_t>::max() / 2
            ? capacity_ * 2 : std::numeric_limits<size_t>::max();
        const size_t nextCapacity = std::max(required, std::max(size_t{4096}, doubled));
        // No value initialization: each byte is written before it is read.
        std::unique_ptr<uint8_t[]> next(new uint8_t[nextCapacity]);
        CopyFront(next.get(), size_);
        data_ = std::move(next);
        capacity_ = nextCapacity;
        head_ = 0;
    }

    std::unique_ptr<uint8_t[]> data_;
    size_t capacity_ = 0;
    size_t head_ = 0;
    size_t size_ = 0;
};

} // namespace hy2::detail
