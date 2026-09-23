#include "hy2/quic_backend/ngtcp2_stream.hpp"
#include "hy2/diag/lock_diag.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>

#include "hy2/debug_print.hpp"
#include "hy2/diag/lock_diag.hpp"
#include "hy2/quic_backend/ngtcp2_connection.hpp"
#include "hy2/diag/lock_diag.hpp"

namespace hy2::quic_backend {

namespace {
// Runtime-gated stream diagnostics (HY2_DIAG=1): per-second byte counts for
// writes/reads plus the state at a stall (pending/unacked vs buffered), so a
// single run shows which side stopped moving.
bool StreamDiagOn() {
    static const bool on = std::getenv("HY2_DIAG") != nullptr;
    return on;
}
void StreamDiag(const char* what, int64_t sid, size_t n, uint64_t a, uint64_t b) {
    if (!StreamDiagOn()) return;
    static std::mutex mu;
    static uint64_t calls = 0, bytes = 0;
    static int64_t nextMs = 0;
    std::lock_guard<std::mutex> lk(mu);
    bytes += n;
    ++calls;
    const int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (nowMs >= nextMs) {
        std::fprintf(stderr, "[stream] %s sid=%lld calls=%llu bytes=%llu last=%zu a=%llu b=%llu\n",
                     what, (long long)sid, (unsigned long long)calls,
                     (unsigned long long)bytes, n, (unsigned long long)a,
                     (unsigned long long)b);
        std::fflush(stderr);
        calls = 0;
        bytes = 0;
        nextMs = nowMs + 1000;
    }
}
}  // namespace

Ngtcp2Stream::Ngtcp2Stream(std::shared_ptr<Ngtcp2Connection> conn, int64_t streamId)
    : conn_(std::move(conn)), streamId_(streamId) {}

Ngtcp2Stream::~Ngtcp2Stream() {
    // Never call back into the connection here: destruction can happen
    // inside ngtcp2 callbacks where driving would re-enter packet
    // encoding (PPE) - just release condition variables.
    {
        hy2::diag::LockTimer _hy2lt_20("ngtcp2_stream:20 readMu_");
          std::lock_guard<std::mutex> lk(readMu_);
          _hy2lt_20.done();
        readClosed_ = true;
        readEof_ = true;
        readCv_.notify_all();
    }
    {
        hy2::diag::LockTimer _hy2lt_26("ngtcp2_stream:26 writeMu_");
          std::lock_guard<std::mutex> lk(writeMu_);
          _hy2lt_26.done();
        writeClosed_ = true;
        writeCv_.notify_all();
    }
}

size_t Ngtcp2Stream::Read(uint8_t* p, size_t n) {
    hy2::diag::LockTimer _hy2lt_33("ngtcp2_stream:33 readMu_");
      std::unique_lock<std::mutex> lk(readMu_);
      _hy2lt_33.done();

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
        // Bounded wait: read notifications are batched (one wakeup per
        // received-packet batch), so a single missed notify used to park this
        // reader forever - after a traffic burst (e.g. seeking in a video) the
        // connection stopped delivering data with no way to recover. The
        // 100 ms tick bounds a lost wakeup to one tick; an idle stream just
        // re-checks its predicate a few times per second.
        while (!pred()) {
            readCv_.wait_for(lk, std::chrono::milliseconds(100));
        }
    }


    if (readPos_ >= readBuf_.size()) {
        return 0; // EOF
    }

    size_t avail = readBuf_.size() - readPos_;
    size_t toRead = std::min(n, avail);
    std::memcpy(p, readBuf_.data() + readPos_, toRead);
    readPos_ += toRead;
    StreamDiag("read", streamId_, toRead, static_cast<uint64_t>(readBuf_.size()),
               static_cast<uint64_t>(readPos_));

    // Compact buffer when fully consumed
    if (readPos_ >= readBuf_.size()) {
        readBuf_.clear();
        readPos_ = 0;
    }

    // Return flow-control credit for the consumed bytes. Consumption (not
    // arrival) drives the window, so the peer can never be more than the
    // initial receive window ahead of the application and readBuf_ stays
    // bounded. Batched to keep the per-read connection-lock traffic low.
    // The readMu_ lock MUST be released before calling into the connection:
    // the receive path holds opMu_ and then readMu_ (OnStreamData), so
    // readMu_ -> opMu_ here would be an ABBA deadlock.
    uint64_t credit = 0;
    recvCreditPending_ += toRead;
    if (recvCreditPending_ >= kRecvCreditBatch) {
        credit = recvCreditPending_;
        recvCreditPending_ = 0;
    }
    lk.unlock();
    if (credit > 0) {
        // Weak lock: a stream the application kept past the connection's
        // lifetime must not touch the freed connection (see conn_ comment).
        if (auto c = conn_.lock()) c->ExtendReadCredit(streamId_, credit);
    }

    return toRead;
}

void Ngtcp2Stream::Write(const uint8_t* p, size_t n) {
    hy2::diag::LockTimer _hy2lt_86("ngtcp2_stream:86 writeMu_");
      std::unique_lock<std::mutex> lk(writeMu_);
      _hy2lt_86.done();
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
    if (auto c = conn_.lock()) c->WakeUpOnData();
    StreamDiag("write", streamId_, n, tailOffset_ - ackedOffset_,
               static_cast<uint64_t>(writeChunks_.size()));
}

void Ngtcp2Stream::Close() {
    // QUIC semantics: this is a HALF-CLOSE (shutdown of the write side).
    // The read side remains usable until the peer sends its own FIN.
    {
        hy2::diag::LockTimer _hy2lt_117("ngtcp2_stream:117 writeMu_");
          std::lock_guard<std::mutex> lk(writeMu_);
          _hy2lt_117.done();
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
        hy2::diag::LockTimer _hy2lt_129("ngtcp2_stream:129 readMu_");
          std::lock_guard<std::mutex> lk(readMu_);
          _hy2lt_129.done();
        readClosed_ = true;
    }
    readCv_.notify_all();
}

void Ngtcp2Stream::CancelWrite(StreamErrorCode code) {
    (void)code;
    {
        hy2::diag::LockTimer _hy2lt_138("ngtcp2_stream:138 writeMu_");
          std::lock_guard<std::mutex> lk(writeMu_);
          _hy2lt_138.done();
        writeClosed_ = true;
        finPending_ = false;
    }
    writeCv_.notify_all();
}

uint64_t Ngtcp2Stream::StreamID() const {
    return static_cast<uint64_t>(streamId_);
}

void Ngtcp2Stream::OnStreamData(const uint8_t* data, size_t len, bool fin) {
    hy2::diag::LockTimer _hy2lt_150("ngtcp2_stream:150 readMu_");
      std::lock_guard<std::mutex> lk(readMu_);
      _hy2lt_150.done();
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
        hy2::diag::LockTimer _hy2lt_164("ngtcp2_stream:164 readMu_");
          std::lock_guard<std::mutex> lk(readMu_);
          _hy2lt_164.done();
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
        hy2::diag::LockTimer _hy2lt_177("ngtcp2_stream:177 readMu_");
          std::lock_guard<std::mutex> lk(readMu_);
          _hy2lt_177.done();
        readEof_ = true;
        readCv_.notify_all();
    }
    {
        hy2::diag::LockTimer _hy2lt_182("ngtcp2_stream:182 writeMu_");
          std::lock_guard<std::mutex> lk(writeMu_);
          _hy2lt_182.done();
        writeClosed_ = true;
        writeCv_.notify_all();
    }
}

void Ngtcp2Stream::OnStreamReset(uint64_t /*finalSize*/, uint64_t appErrorCode) {
    OnStreamClose(appErrorCode);
}

void Ngtcp2Stream::OnAckedStreamData(uint64_t offset, uint64_t datalen) {
    hy2::diag::LockTimer _hy2lt_193("ngtcp2_stream:193 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_193.done();
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
    hy2::diag::LockTimer _hy2lt_237("ngtcp2_stream:237 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_237.done();
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
    hy2::diag::LockTimer _hy2lt_260("ngtcp2_stream:260 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_260.done();
    // Note: a locally-closed stream still needs to flush queued data + FIN.
    return sentOffset_ < tailOffset_ || finPending_;
}

bool Ngtcp2Stream::FinPending() const {
    hy2::diag::LockTimer _hy2lt_266("ngtcp2_stream:266 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_266.done();
    return finPending_;
}

void Ngtcp2Stream::AdvanceWrite(size_t n) {
    hy2::diag::LockTimer _hy2lt_271("ngtcp2_stream:271 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_271.done();
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
    hy2::diag::LockTimer _hy2lt_283("ngtcp2_stream:283 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_283.done();
    finPending_ = false;
}

void Ngtcp2Stream::SetFinPending() {
    hy2::diag::LockTimer _hy2lt_288("ngtcp2_stream:288 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_288.done();
    finPending_ = true;
}

bool Ngtcp2Stream::IsClosed() const {
    return closed_;
}

void Ngtcp2Stream::DiagPrint() {
    std::unique_lock<std::mutex> rl(readMu_, std::try_to_lock);
    std::unique_lock<std::mutex> wl(writeMu_, std::try_to_lock);
    std::fprintf(stderr,
                 "[hb-stream] sid=%lld read=%s buf=%zu pos=%zu eof=%d dirty=%d rclosed=%d | "
                 "write=%s tail=%llu sent=%llu acked=%llu chunks=%zu cursor=%zu fin=%d wclosed=%d\n",
                 (long long)streamId_, rl.owns_lock() ? "ok" : "LOCKED",
                 readBuf_.size(), readPos_, (int)readEof_, (int)readDirty_, (int)readClosed_,
                 wl.owns_lock() ? "ok" : "LOCKED", (unsigned long long)tailOffset_,
                 (unsigned long long)sentOffset_, (unsigned long long)ackedOffset_,
                 writeChunks_.size(), cursor_, (int)finPending_, (int)writeClosed_);
    std::fflush(stderr);
}

} // namespace hy2::quic_backend