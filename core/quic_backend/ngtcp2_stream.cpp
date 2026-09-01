#include "hy2/quic_backend/ngtcp2_stream.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#include "hy2/debug_print.hpp"
#include "hy2/quic_backend/ngtcp2_connection.hpp"

namespace hy2::quic_backend {

Ngtcp2Stream::Ngtcp2Stream(Ngtcp2Connection* conn, int64_t streamId)
    : conn_(conn), streamId_(streamId) {}

Ngtcp2Stream::~Ngtcp2Stream() {
    // Never call back into the connection here: destruction can happen
    // inside ngtcp2 callbacks where driving would re-enter packet
    // encoding (PPE) - just release condition variables.
    {
        std::lock_guard<std::mutex> lk(readMu_);
        readClosed_ = true;
        readEof_ = true;
        readCv_.notify_all();
    }
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        writeClosed_ = true;
        writeCv_.notify_all();
    }
}

size_t Ngtcp2Stream::Read(uint8_t* p, size_t n) {
    std::unique_lock<std::mutex> lk(readMu_);

    // Wait for data or EOF — support deadline for timeout
    auto pred = [this] {
        return readBuf_.size() > readPos_ || readEof_ || readClosed_;
    };
    if (readDeadline_.ns > 0) {
        auto tp = std::chrono::steady_clock::time_point(
            std::chrono::nanoseconds(readDeadline_.ns));
        // Use polling wait: check deadline every 100ms
        while (!pred()) {
            auto now = std::chrono::steady_clock::now();
            if (now >= tp) {
                break;
            }
            auto remaining = std::min(
                std::chrono::milliseconds(100),
                std::chrono::duration_cast<std::chrono::milliseconds>(tp - now));
            readCv_.wait_for(lk, remaining, pred);
            if (pred()) break;
        }
    } else {
        readCv_.wait(lk, pred);
    }

    if (readPos_ >= readBuf_.size()) {
        return 0; // EOF
    }

    size_t avail = readBuf_.size() - readPos_;
    size_t toRead = std::min(n, avail);
    std::memcpy(p, readBuf_.data() + readPos_, toRead);
    readPos_ += toRead;

    // Compact buffer when fully consumed
    if (readPos_ >= readBuf_.size()) {
        readBuf_.clear();
        readPos_ = 0;
    }

    return toRead;
}

void Ngtcp2Stream::Write(const uint8_t* p, size_t n) {
    std::unique_lock<std::mutex> lk(writeMu_);
    if (writeClosed_) {
        DBG_LOG("Ngtcp2Stream::Write: write side closed, stream_id", streamId_);
        throw hy2::Error("write side closed");
    }

    // Backpressure: an unbounded sender (bwtest hammers Write() with no
    // pacing) would otherwise pile up hundreds of MB in writeBuf_ while the
    // peer's cwnd recovers — stalling Drive via lock contention and memory
    // churn. Cap the pending queue at a few cwnds' worth and block until
    // Drive() drains it (woken by AdvanceWrite, no polling).
    constexpr size_t kMaxWriteBuf = 8 * 1024 * 1024;
    while (writeBuf_.size() > kMaxWriteBuf && !writeClosed_) {
        writeCv_.wait_for(lk, std::chrono::milliseconds(100), [this] {
            return writeBuf_.size() <= kMaxWriteBuf || writeClosed_;
        });
    }
    if (writeClosed_) {
        throw hy2::Error("write side closed");
    }

    writeBuf_.insert(writeBuf_.end(), p, p + n);
    DBG_LOG("Ngtcp2Stream::Write: appended", "stream_id", streamId_,
            "bytes", n, "buf_size", writeBuf_.size());
    // Wake the event-loop thread so it flushes pending data immediately.
    // Edge-triggered: repeated writes inside one burst only pay the pipe
    // syscall once per false->true transition of the pending flag.
    if (conn_) conn_->WakeUpOnData();
}

void Ngtcp2Stream::Close() {
    // QUIC semantics: this is a HALF-CLOSE (shutdown of the write side).
    // The read side remains usable until the peer sends its own FIN.
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        if (!writeClosed_) {
            writeClosed_ = true;
            finPending_ = true; // send FIN with the last data
        }
        writeCv_.notify_all();
    }
}

void Ngtcp2Stream::CancelRead(StreamErrorCode code) {
    (void)code;
    {
        std::lock_guard<std::mutex> lk(readMu_);
        readClosed_ = true;
    }
    readCv_.notify_all();
}

void Ngtcp2Stream::CancelWrite(StreamErrorCode code) {
    (void)code;
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        writeClosed_ = true;
        finPending_ = false;
    }
    writeCv_.notify_all();
}

uint64_t Ngtcp2Stream::StreamID() const {
    return static_cast<uint64_t>(streamId_);
}

void Ngtcp2Stream::OnStreamData(const uint8_t* data, size_t len, bool fin) {
    std::lock_guard<std::mutex> lk(readMu_);
    if (len > 0) {
        readBuf_.insert(readBuf_.end(), data, data + len);
    }
    if (fin) {
        readEof_ = true;
    }
    readCv_.notify_all();
}

void Ngtcp2Stream::OnStreamClose(uint64_t /*appErrorCode*/) {
    {
        std::lock_guard<std::mutex> lk(readMu_);
        readEof_ = true;
        readCv_.notify_all();
    }
    {
        std::lock_guard<std::mutex> lk(writeMu_);
        writeClosed_ = true;
        writeCv_.notify_all();
    }
}

void Ngtcp2Stream::OnStreamReset(uint64_t /*finalSize*/, uint64_t appErrorCode) {
    OnStreamClose(appErrorCode);
}

void Ngtcp2Stream::OnAckedStreamData(uint64_t /*offset*/, uint64_t datalen) {
    // Note: no writeCv_ notify here - an ACK does not change writeBuf_
    // (that only happens in CopyPendingWrite/AdvanceWrite), so it cannot
    // unblock a backpressure-waiting Write().
    std::lock_guard<std::mutex> lk(writeMu_);
    writeAckedPos_ += datalen;
}

bool Ngtcp2Stream::CopyPendingWrite(uint8_t* dst, size_t cap, size_t* outLen,
                                    bool* outFin) {
    std::lock_guard<std::mutex> lk(writeMu_);
    *outFin = finPending_;
    if (writeBuf_.empty()) {
        *outLen = 0;
        return finPending_;
    }
    size_t n = std::min(cap, writeBuf_.size());
    std::copy_n(writeBuf_.begin(), n, dst);
    *outLen = n;
    return true;
}

bool Ngtcp2Stream::HasPendingWrite() const {
    std::lock_guard<std::mutex> lk(writeMu_);
    // Note: a locally-closed stream still needs to flush queued data + FIN.
    return !writeBuf_.empty() || finPending_;
}

bool Ngtcp2Stream::FinPending() const {
    std::lock_guard<std::mutex> lk(writeMu_);
    return finPending_;
}

void Ngtcp2Stream::AdvanceWrite(size_t n) {
    std::lock_guard<std::mutex> lk(writeMu_);
    if (n >= writeBuf_.size()) {
        writeBuf_.clear();
    } else {
        // Front-erase on a deque destroys only the consumed elements; the
        // remaining backlog is not shifted (a vector would memmove it all).
        writeBuf_.erase(writeBuf_.begin(),
                        writeBuf_.begin() + static_cast<std::ptrdiff_t>(n));
    }
    // Wake any Write() blocked by the backpressure cap.
    writeCv_.notify_all();
}

void Ngtcp2Stream::ClearFinPending() {
    std::lock_guard<std::mutex> lk(writeMu_);
    finPending_ = false;
}

void Ngtcp2Stream::SetFinPending() {
    std::lock_guard<std::mutex> lk(writeMu_);
    finPending_ = true;
}

bool Ngtcp2Stream::IsClosed() const {
    return closed_;
}

} // namespace hy2::quic_backend
