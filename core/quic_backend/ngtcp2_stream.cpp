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
        return readBuf_.size() > 0 || readEof_ || readClosed_;
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


    if (readBuf_.size() == 0) {
        // FIN can arrive separately after the last data read. Flush its tail
        // even when the caller keeps the write half open after EOF.
        const uint64_t credit = recvCreditPending_;
        recvCreditPending_ = 0;
        lk.unlock();
        if (credit > 0) {
            if (auto c = conn_.lock()) c->ExtendReadCredit(streamId_, credit);
        }
        return 0; // EOF
    }

    const size_t toRead = readBuf_.Read(p, n);
    StreamDiag("read", streamId_, toRead, static_cast<uint64_t>(readBuf_.size()),
               static_cast<uint64_t>(readBuf_.capacity()));

    // Return flow-control credit for the consumed bytes. Consumption (not
    // arrival) drives the window, so the peer can never be more than the
    // initial receive window ahead of the application and readBuf_ stays
    // bounded. Batched to keep the per-read connection-lock traffic low.
    // The readMu_ lock MUST be released before calling into the connection:
    // the receive path holds opMu_ and then readMu_ (OnStreamData), so
    // readMu_ -> opMu_ here would be an ABBA deadlock.
    uint64_t credit = 0;
    recvCreditPending_ += toRead;
    if (recvCreditPending_ >= kRecvCreditBatch || (readEof_ && readBuf_.size() == 0)) {
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
    if (tailOffset_.load(std::memory_order_relaxed) - ackedOffset_ > kMaxWriteBuf &&
        !writeClosed_) {
        writeBlockedCount_.fetch_add(1, std::memory_order_relaxed);
        const auto blockedStart = std::chrono::steady_clock::now();
        while (tailOffset_.load(std::memory_order_relaxed) - ackedOffset_ > kMaxWriteBuf &&
               !writeClosed_) {
            writeCv_.wait_for(lk, std::chrono::milliseconds(100), [this] {
                return tailOffset_.load(std::memory_order_relaxed) - ackedOffset_ <= kMaxWriteBuf ||
                       writeClosed_;
            });
        }
        writeBlockedNs_.fetch_add(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - blockedStart).count()),
            std::memory_order_relaxed);
    }
    if (writeClosed_) {
        throw hy2::Error("write side closed");
    }

    AppendWriteLocked(p, n);
    DBG_LOG("Ngtcp2Stream::Write: appended", "stream_id", streamId_,
            "bytes", n, "unacked", tailOffset_.load(std::memory_order_relaxed) - ackedOffset_);
    // Wake the event-loop thread so it flushes pending data immediately.
    // Edge-triggered: repeated writes inside one burst only pay the pipe
    // syscall once per false->true transition of the pending flag.
    if (auto c = conn_.lock()) c->WakeUpOnData();
    StreamDiag("write", streamId_, n, tailOffset_.load(std::memory_order_relaxed) - ackedOffset_,
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
            finPending_.store(true, std::memory_order_relaxed); // send FIN with the last data
        }
        writeCv_.notify_all();
    }
    if (auto c = conn_.lock()) c->WakeUpOnData();
}

void Ngtcp2Stream::CancelRead(StreamErrorCode code) {
    // Flow-control credit for data this stream received but the application
    // will never read. Two pools of it:
    //   1. recvCreditPending_ - consumed-but-not-yet-flushed (< 256 KB by
    //      definition, see kRecvCreditBatch);
    //   2. readBuf_ unread tail - DELIVERED to the application level but
    //      never Read(), so its ExtendReadCredit never ran. Without handing
    //      this back, every abandoned stream permanently ate that many bytes
    //      of the CONNECTION-level window (16 MB): enough seeks and the whole
    //      QUIC connection stalled at 0 B/s even though it was perfectly
    //      healthy - the exact "seek once, then 0 KB/s" report.
    //      (Data still buffered inside ngtcp2 itself is credited by ngtcp2
    //      automatically once STOP_SENDING is set - see its
    //      conn_recv_stream's discard path - so only the delivered-to-app
    //      tail is ours to return.)
    uint64_t credit = 0;
    bool abort = false;
    {
        hy2::diag::LockTimer _hy2lt_129("ngtcp2_stream:129 readMu_");
          std::lock_guard<std::mutex> lk(readMu_);
          _hy2lt_129.done();
        abort = !readEof_;
        readClosed_ = true;
        credit += recvCreditPending_;
        recvCreditPending_ = 0;
        credit += readBuf_.size();
        readBuf_.clear();
        // If the peer already FINed, it has nothing more to send and a
        // graceful half-close is the right answer; STOP_SENDING would only
        // turn every normal completion into an abort. The credit above is
        // still owed in full.
    }
    readCv_.notify_all();
    // readMu_ MUST be released before touching the connection (see the
    // ExtendReadCredit comment: recv path takes opMu_ -> readMu_).
    if (auto c = conn_.lock()) {
        // Credit the connection window for the unread tail, then abort the
        // stream - same op, so the credit and the STOP_SENDING land together.
        if (abort) {
            c->ShutdownStreamEx(streamId_, static_cast<uint64_t>(code), credit);
        } else if (credit > 0) {
            c->ExtendReadCredit(streamId_, credit);
        }
    }
}

void Ngtcp2Stream::CancelWrite(StreamErrorCode code) {
    {
        hy2::diag::LockTimer _hy2lt_138("ngtcp2_stream:138 writeMu_");
          std::lock_guard<std::mutex> lk(writeMu_);
          _hy2lt_138.done();
        writeClosed_ = true;
        finPending_.store(false, std::memory_order_relaxed);
    }
    writeCv_.notify_all();
    if (auto c = conn_.lock()) {
        c->ShutdownStream(streamId_, static_cast<uint64_t>(code));
    }
}

uint64_t Ngtcp2Stream::StreamID() const {
    return static_cast<uint64_t>(streamId_);
}

void Ngtcp2Stream::OnStreamData(const uint8_t* data, size_t len, bool fin) {
    hy2::diag::LockTimer _hy2lt_150("ngtcp2_stream:150 readMu_");
      std::lock_guard<std::mutex> lk(readMu_);
      _hy2lt_150.done();
    if (len > 0) {
        readBuf_.Append(data, len);
    }
    if (fin) {
        readEof_ = true;
    }
    // No notify here: the connection flushes one wakeup per recv batch.
    readDirty_.store(true, std::memory_order_release);
}

void Ngtcp2Stream::FlushReadNotify() {
    // Lock-free check: exchange(false) atomically tests and clears the dirty flag
    // without contending on readMu_ with the reader thread.
    if (readDirty_.exchange(false, std::memory_order_acq_rel)) {
        readCv_.notify_all();
    }
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
    const bool wasBlocked =
        tailOffset_.load(std::memory_order_relaxed) - ackedOffset_ > kMaxWriteBuf;
    ackedOffset_ = acked;
    DropAckedLocked();
    if (wasBlocked &&
        tailOffset_.load(std::memory_order_relaxed) - ackedOffset_ <= kMaxWriteBuf) {
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
            writeChunks_.back().baseOffset = tailOffset_.load(std::memory_order_relaxed);
            writeChunks_.back().data.reserve(kWriteChunkSize);
        }
        WriteChunk& back = writeChunks_.back();
        size_t space = kWriteChunkSize - back.data.size();
        size_t take = std::min(space, n);
        back.data.insert(back.data.end(), p, p + take);
        tailOffset_.store(tailOffset_.load(std::memory_order_relaxed) + take,
                          std::memory_order_relaxed);
        p += take;
        n -= take;
    }
}

const uint8_t* Ngtcp2Stream::PeekPendingWrite(size_t* len, bool* fin) {
    hy2::diag::LockTimer _hy2lt_237("ngtcp2_stream:237 writeMu_");
      std::lock_guard<std::mutex> lk(writeMu_);
      _hy2lt_237.done();
    *fin = finPending_.load(std::memory_order_relaxed);
    if (sentOffset_.load(std::memory_order_relaxed) >=
            tailOffset_.load(std::memory_order_relaxed) ||
        writeChunks_.empty()) {
        *len = 0;
        return nullptr;
    }
    // The send cursor may have moved past chunks that are still unacked
    // (they are kept for retransmission), so walk to the chunk that covers
    // sentOffset_. cursor_ makes this O(1) amortized.
    while (cursor_ < writeChunks_.size()) {
        const WriteChunk& c = writeChunks_[cursor_];
        const uint64_t sent = sentOffset_.load(std::memory_order_relaxed);
        if (sent < c.baseOffset + c.data.size()) {
            const size_t off = static_cast<size_t>(sent - c.baseOffset);
            *len = c.data.size() - off;
            return c.data.data() + off;
        }
        ++cursor_;
    }
    *len = 0;
    return nullptr;
}

bool Ngtcp2Stream::HasPendingWrite() const {
    // Deliberately lock-free: the connection calls this once per stream on
    // every IO iteration to find the next stream with data
    // (PickWritableStreamLocked), so N streams used to mean N mutex pairs per
    // iteration. The three fields are atomic and every writer still holds
    // writeMu_, so this reads live values; a stale one only costs another look,
    // because every append is followed by WakeUpOnData().
    // Note: a locally-closed stream still needs to flush queued data + FIN.
    return sentOffset_.load(std::memory_order_relaxed) <
               tailOffset_.load(std::memory_order_relaxed) ||
           finPending_.load(std::memory_order_relaxed);
}

bool Ngtcp2Stream::FinPending() const {
    return finPending_.load(std::memory_order_relaxed);
}

void Ngtcp2Stream::AdvanceWrite(size_t n) {
    if (n == 0) return;
    // Lock-free cursor advance: the bytes stay buffered until the peer acks
    // them, because ngtcp2 re-reads them for retransmissions. Freeing happens
    // in OnAckedStreamData()/DropAckedLocked().
    uint64_t sent = sentOffset_.load(std::memory_order_relaxed);
    for (;;) {
        const uint64_t tail = tailOffset_.load(std::memory_order_acquire);
        const uint64_t nextSent = (static_cast<uint64_t>(n) > tail - sent) ? tail : (sent + n);
        if (sentOffset_.compare_exchange_weak(sent, nextSent,
                                              std::memory_order_release,
                                              std::memory_order_relaxed)) {
            break;
        }
    }
}

void Ngtcp2Stream::ClearFinPending() {
    finPending_.store(false, std::memory_order_release);
}

void Ngtcp2Stream::SetFinPending() {
    finPending_.store(true, std::memory_order_release);
}

bool Ngtcp2Stream::IsClosed() const {
    return closed_;
}

void Ngtcp2Stream::DiagPrint() {
    std::unique_lock<std::mutex> rl(readMu_, std::try_to_lock);
    std::unique_lock<std::mutex> wl(writeMu_, std::try_to_lock);
    std::fprintf(stderr,
                 "[hb-stream] sid=%lld read=%s buf=%zu capacity=%zu eof=%d dirty=%d rclosed=%d | "
                 "write=%s tail=%llu sent=%llu acked=%llu chunks=%zu cursor=%zu fin=%d wclosed=%d\n",
                 (long long)streamId_, rl.owns_lock() ? "ok" : "LOCKED",
                 rl.owns_lock() ? readBuf_.size() : 0, rl.owns_lock() ? readBuf_.capacity() : 0,
                 rl.owns_lock() ? (int)readEof_ : -1, (int)readDirty_.load(std::memory_order_relaxed), rl.owns_lock() ? (int)readClosed_ : -1,
                 wl.owns_lock() ? "ok" : "LOCKED",
                 (unsigned long long)tailOffset_.load(std::memory_order_relaxed),
                 (unsigned long long)sentOffset_.load(std::memory_order_relaxed),
                 (unsigned long long)(wl.owns_lock() ? ackedOffset_ : 0),
                 wl.owns_lock() ? writeChunks_.size() : 0, wl.owns_lock() ? cursor_ : 0,
                 (int)finPending_.load(std::memory_order_relaxed), wl.owns_lock() ? (int)writeClosed_ : -1);
    std::fflush(stderr);
}

} // namespace hy2::quic_backend
