// io.hpp - Minimal IO abstractions mirroring Go's io.Reader/Writer/Conn,
// plus a Go-style buffered channel used by the UDP session managers.
#pragma once

#include <algorithm>
#include <condition_variable>
#include <cstdint>
#include <cstddef>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

#include "common.hpp"
#include "hy2/debug_print.hpp"
#include "error.hpp"

namespace hy2 {

// ---------------------------------------------------------------------------
// Reader/Writer interfaces.
//
// Read semantics (mirroring Go's io.Reader with exceptions):
//   - returns number of bytes read (>0). May be less than requested.
//   - returns 0 and throws nothing => clean EOF.
//   - throws Error subclass on failure (closed conn etc.).
class IByteReader {
public:
    virtual ~IByteReader() = default;
    virtual size_t Read(uint8_t* p, size_t n) = 0;
};

// Write throws on error. Mirrors io.Writer's (n, err) with n==len(p) on success.
class IByteWriter {
public:
    virtual ~IByteWriter() = default;
    virtual void Write(const uint8_t* p, size_t n) = 0;
};

// IByteReaderWriter combines the read/write interfaces (io.ReadWriter).
class IByteReaderWriter : public IByteReader, public IByteWriter {
public:
    // Close unblocks pending readers/writers where supported (default no-op).
    virtual void Close() {}
};

// ReadFull reads exactly len(buf) bytes or throws (short read => EOF as Error).
inline void ReadFull(IByteReader& r, uint8_t* buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        size_t got = r.Read(buf + off, n - off);
        if (got == 0) {
            throw Error("unexpected EOF");
        }
        off += got;
    }
}

// DiscardN reads and discards exactly n bytes or throws.
inline void DiscardN(IByteReader& r, size_t n) {
    uint8_t tmp[512];
    size_t off = 0;
    while (off < n) {
        size_t chunk = std::min(sizeof(tmp), n - off);
        size_t got = r.Read(tmp, chunk);
        if (got == 0) throw Error("unexpected EOF");
        off += got;
    }
}

// A simple in-memory reader over a byte buffer (used by protocol parsing tests).
class SliceReader : public IByteReader {
public:
    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;

    SliceReader(const uint8_t* data, size_t len) : data_(data), len_(len) {}
    explicit SliceReader(const std::vector<uint8_t>& v) : data_(v.data()), len_(v.size()) {}

    size_t Read(uint8_t* p, size_t n) override {
        if (pos_ >= len_) return 0;
        size_t got = std::min(n, len_ - pos_);
        std::copy(data_ + pos_, data_ + pos_ + got, p);
        pos_ += got;
        return got;
    }
};

// ---------------------------------------------------------------------------
// HyStream mirrors server.HyStream / utils.QStream surface:
// a bidirectional QUIC stream wrapper.
enum class StreamErrorCode : uint64_t { None = 0 };

class IHyStream : public IByteReaderWriter {
public:
    virtual uint64_t StreamID() const = 0;
    // Close closes the write side and cancels pending reads (QStream semantics:
    // CancelRead(0) followed by stream close).
    virtual void Close() = 0;
    virtual void CancelRead(StreamErrorCode code) = 0;
    virtual void CancelWrite(StreamErrorCode code) = 0;
    // Deadline support (no-op deadline = zero time); implementations may ignore.
    virtual void SetReadDeadline(MonoTime t) { (void)t; }
    virtual void SetWriteDeadline(MonoTime t) { (void)t; }
    virtual void SetDeadline(MonoTime t) { (void)t; }
};

// ---------------------------------------------------------------------------
// Channel<T> - Go-style buffered channel with close semantics.
// Send on closed channel throws; Receive on closed+empty channel returns false.
template <typename T>
class Channel {
public:
    explicit Channel(size_t capacity) : cap_(capacity == 0 ? 1 : capacity) {}

    // TrySend: drops the value when the buffer is full (like Go select/default
    // usage in udp.go feed()). Returns false if dropped or closed.
    bool TrySend(T v) {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return false;
        if (q_.size() >= cap_) return false;
        q_.push_back(std::move(v));
        cv_.notify_one();
        return true;
    }

    // Send blocks until space is available. Throws if the channel is closed.
    void Send(T v) {
        DBG_LOG("Channel::Send: waiting for space");
        std::unique_lock<std::mutex> lk(mu_);
        sendCv_.wait(lk, [&] { return closed_ || q_.size() < cap_; });
        if (closed_) {
            DBG_LOG("Channel::Send: channel closed, throwing");
            throw Error("send on closed channel");
        }
        q_.push_back(std::move(v));
        DBG_LOG("Channel::Send: sent, queue_size", q_.size());
        cv_.notify_one();
    }

    // Receive blocks. Returns (ok=false) when the channel is closed and drained.
    bool Receive(T& out) {
        DBG_LOG("Channel::Receive: waiting for data");
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return closed_ || !q_.empty(); });
        if (q_.empty()) {
            DBG_LOG("Channel::Receive: closed and drained");
            return false; // closed & drained
        }
        out = std::move(q_.front());
        q_.pop_front();
        DBG_LOG("Channel::Receive: received, queue_size", q_.size());
        sendCv_.notify_one();
        return true;
    }

    // ReceiveFor blocks up to timeout. Returns false on timeout or closed.
    template<class Rep, class Period>
    bool ReceiveFor(T& out, std::chrono::duration<Rep, Period> timeout) {
        std::unique_lock<std::mutex> lk(mu_);
        if (!cv_.wait_for(lk, timeout, [&] { return closed_ || !q_.empty(); })) {
            return false; // timeout
        }
        if (q_.empty()) return false; // closed & drained
        out = std::move(q_.front());
        q_.pop_front();
        sendCv_.notify_one();
        return true;
    }

    void Close() {
        std::lock_guard<std::mutex> lk(mu_);
        closed_ = true;
        cv_.notify_all();
        sendCv_.notify_all();
    }

    bool Closed() const {
        std::lock_guard<std::mutex> lk(mu_);
        return closed_;
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::condition_variable sendCv_;
    std::deque<T> q_;
    size_t cap_;
    bool closed_ = false;
};

} // namespace hy2
