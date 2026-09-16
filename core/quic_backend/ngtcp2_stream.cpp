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

    // Backpressure on unacknowledged bytes: block until the peer acks enough
    // of the backlog (OnAckedStreamData wakes us; the timed wait is only a
    // safety net).
    while (tailOffset_ - ackedOffset_ > kMaxWriteBuf && !writeClosed_) {
        writeCv_.wait_for(lk, std::chrono::milliseconds(100), [this] {
            return tailOffset_ - ackedOffset_ <= kMaxWriteBuf || writeClosed_;
        });
    }
    if (writeClosed_) {
        throw hy2::Error("write side closed");
    }

    AppendWriteLocked(p, n);
    DBG_LOG("Ngtcp2Stream::Write: appended", "stream_id", streamId_,
            "bytes", n, "unacked", tailOffset_ - ackedOffset_);
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
    // No notify here: the connection flushes one wakeup per recv batch.
    readDirty_ = true;
}

void Ngtcp2Stream::FlushReadNotify() {
    bool need = false;
    {
        std::lock_guard<std::mutex> lk(readMu_);
        if (readDirty_) {
            readDirty_ = false;
            need = true;
        }
    }
    // Notify with the mutex released: the woken reader re-acquires readMu_
    // immediately, so holding it here would make it spin first.
    if (need) readCv_.notify_all();
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

void Ngtcp2Stream::OnAckedStreamData(uint64_t offset, uint64_t datalen) {
    std::lock_guard<std::mutex> lk(writeMu_);
    // ngtcp2 reports the largest *gap-free* acked offset, i.e. everything
    // below it is safe to release (retransmissions can no longer need it).
    const uint64_t acked = offset + datalen;
    if (acked <= ackedOffset_) return;
    const bool wasBlocked = tailOffset_ - ackedOffset_ > kMaxWriteBuf;
    ackedOffset_ = acked;
    DropAckedLocked();
    if (wasBlocked && tailOffset_ - ackedOffset_ <= kMaxWriteBuf) {
        writeCv_.notify_all();
    }
}

void Ngtcp2Stream::DropAckedLocked() {
    // Caller holds writeMu_. Frees every chunk whose bytes are fully acked.
    while (!writeChunks_.empty()) {
        const WriteChunk& front = writeChunks_.front();
        if (front.baseOffset + front.data.size() > ackedOffset_) break;
        writeChunks_.pop_front();
        if (cursor_ > 0) --cursor_;
    }
}

void Ngtcp2Stream::AppendWriteLocked(const uint8_t* p, size_t n) {
    // Caller holds writeMu_. Fills the tail chunk, then adds new 64 KB
    // chunks. One memcpy per chunk instead of one allocation per element.
    while (n > 0) {
        if (writeChunks_.empty() ||
            writeChunks_.back().data.size() >= kWriteChunkSize) {
            writeChunks_.emplace_back();
            writeChunks_.back().baseOffset = tailOffset_;
            writeChunks_.back().data.reserve(kWriteChunkSize);
        }
        WriteChunk& back = writeChunks_.back();
        size_t space = kWriteChunkSize - back.data.size();
        size_t take = std::min(space, n);
        back.data.insert(back.data.end(), p, p + take);
        tailOffset_ += take;
        p += take;
        n -= take;
    }
}

const uint8_t* Ngtcp2Stream::PeekPendingWrite(size_t* len, bool* fin) {
    std::lock_guard<std::mutex> lk(writeMu_);
    *fin = finPending_;
    if (sentOffset_ >= tailOffset_ || writeChunks_.empty()) {
        *len = 0;
        return nullptr;
    }
    // The send cursor may have moved past chunks that are still unacked
    // (they are kept for retransmission), so walk to the chunk that covers
    // sentOffset_. cursor_ makes this O(1) amortized.
    while (cursor_ < writeChunks_.size()) {
        const WriteChunk& c = writeChunks_[cursor_];
        if (sentOffset_ < c.baseOffset + c.data.size()) {
            const size_t off = static_cast<size_t>(sentOffset_ - c.baseOffset);
            *len = c.data.size() - off;
            return c.data.data() + off;
        }
        ++cursor_;
    }
    *len = 0;
    return nullptr;
}

bool Ngtcp2Stream::HasPendingWrite() const {
    std::lock_guard<std::mutex> lk(writeMu_);
    // Note: a locally-closed stream still needs to flush queued data + FIN.
    return sentOffset_ < tailOffset_ || finPending_;
}

bool Ngtcp2Stream::FinPending() const {
    std::lock_guard<std::mutex> lk(writeMu_);
    return finPending_;
}

void Ngtcp2Stream::AdvanceWrite(size_t n) {
    std::lock_guard<std::mutex> lk(writeMu_);
    // Only move the send cursor: the bytes stay buffered until the peer acks
    // them, because ngtcp2 re-reads them for retransmissions. Freeing happens
    // in OnAckedStreamData()/DropAckedLocked().
    if (static_cast<uint64_t>(n) > tailOffset_ - sentOffset_) {
        sentOffset_ = tailOffset_;  // defensive: never run past the tail
    } else {
        sentOffset_ += n;
    }
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
