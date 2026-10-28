#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

#include <ngtcp2/ngtcp2.h>

#include "hy2/quic.hpp"
#include "hy2/detail/receive_buffer.hpp"

namespace hy2::quic_backend {

class Ngtcp2Connection;

// ---------------------------------------------------------------------------
// Ngtcp2Stream: wraps a single ngtcp2 stream, implements IQuicStream.
// Created by Ngtcp2Connection::OpenStream() or when a remote-initiated
// stream arrives via the stream_open callback.
// ---------------------------------------------------------------------------
class Ngtcp2Stream : public IQuicStream {
    friend class Ngtcp2Connection;

public:
    ~Ngtcp2Stream() override;

    // IByteReader
    size_t Read(uint8_t* p, size_t n) override;

    // IByteWriter
    void Write(const uint8_t* p, size_t n) override;

    // IHyStream
    void Close() override;
    void CancelRead(StreamErrorCode code) override;
    void CancelWrite(StreamErrorCode code) override;
    uint64_t StreamID() const override;

    void SetReadDeadline(MonoTime t) override { readDeadline_ = t; }
    void SetWriteDeadline(MonoTime t) override { writeDeadline_ = t; }

    // Called by Ngtcp2Connection when data arrives on this stream.
    // Does NOT wake a blocked reader: it only marks the stream dirty. The
    // connection calls FlushReadNotify() once per received batch, so a
    // 60-packet burst costs one reader wakeup instead of 60. Both sides
    // used to pay a full condition-variable round trip per packet.
    void OnStreamData(const uint8_t* data, size_t len, bool fin);

    // Wake a reader blocked in Read() if new data/EOF arrived since the last
    // flush. Safe to call on any stream (no-op when nothing changed).
    void FlushReadNotify();

    // Called by Ngtcp2Connection when the peer closes/resets this stream.
    void OnStreamClose(uint64_t appErrorCode);
    void OnStreamReset(uint64_t finalSize, uint64_t appErrorCode);

    // Called by Ngtcp2Connection when data is acked (write buffer drain).
    void OnAckedStreamData(uint64_t offset, uint64_t datalen);

    // Write-side plumbing used by Ngtcp2Connection::Drive():
    // Zero-copy: returns a pointer to the next contiguous run of unsent write
    // data. The pointer stays valid until the peer acknowledges those bytes -
    // ngtcp2 re-reads every submitted byte when a packet must be retransmitted
    // ("the caller must keep the portion of data covered by *pdatalen intact
    // until acked_stream_data_offset indicates that they are acknowledged").
    // Drive() calls AdvanceWrite() right after ngtcp2_conn_writev_stream()
    // returns, which only advances the send cursor, never frees the chunk.
    // Returns nullptr with *len == 0 when no data is pending; *fin reports
    // a queued FIN.
    const uint8_t* PeekPendingWrite(size_t* len, bool* fin);
    bool HasPendingWrite() const;
    bool FinPending() const;
    // Marks n bytes as handed to ngtcp2 (the data stays buffered for
    // retransmission until the peer acks it).
    void AdvanceWrite(size_t n);
    void ClearFinPending();
    // Mark the local write side finished (sends FIN).
    void SetFinPending();

    bool IsClosed() const;

    // HY2_DIAG stall helper: prints the stream's read/write state. Uses
    // try_lock so it never blocks the caller; reports whether a lock is held.
    void DiagPrint();

private:
    Ngtcp2Stream(std::shared_ptr<Ngtcp2Connection> conn, int64_t streamId);

    // Weak, not raw: the application can hold a stream after the connection it
    // belongs to is gone (the client pool drops its Client on a node switch,
    // after which the connection is kept alive only by its own IO thread and is
    // freed the moment that loop exits). Read()/Write() must therefore never
    // dereference the connection directly - lock() fails once the connection's
    // strong count reaches zero, so a detached stream simply stops notifying.
    std::weak_ptr<Ngtcp2Connection> conn_;
    int64_t streamId_ = 0;

    mutable std::mutex readMu_;
    hy2::detail::ReceiveBuffer readBuf_;
    bool readEof_ = false;
    bool readClosed_ = false;
    // Set by OnStreamData, cleared by FlushReadNotify (lock-free via atomic exchange).
    std::atomic<bool> readDirty_{false};
    // Bytes consumed by the application but not yet returned to the peer as
    // flow-control credit (guarded by readMu_). Credit is returned in batches
    // to keep the per-read connection-lock traffic low; the receive window
    // stays bounded because credit is only ever returned for consumed bytes.
    uint64_t recvCreditPending_ = 0;
    static constexpr uint64_t kRecvCreditBatch = 256 * 1024;

    mutable std::mutex writeMu_;
    // Chunked buffer holding every byte that is not acknowledged yet: ngtcp2
    // keeps references to the submitted data and re-reads it on
    // retransmissions, so a chunk can only be released once the contiguous
    // acked offset (ngtcp2 hands us the largest gap-free offset) passes its
    // end. Encoding a packet therefore no longer frees anything - it only
    // moves the send cursor. Large pre-reserved chunks keep appends
    // O(1)-amortized and give the send path one memcpy per packet.
    static constexpr size_t kWriteChunkSize = 64 * 1024;
    struct WriteChunk {
        std::vector<uint8_t> data;
        uint64_t baseOffset = 0;  // absolute stream offset of data[0]
    };
    std::deque<WriteChunk> writeChunks_;
    size_t cursor_ = 0;         // index of the chunk that holds sentOffset_
    uint64_t ackedOffset_ = 0;  // largest gap-free offset acked by the peer
    // sentOffset_/tailOffset_/finPending_ are the entire predicate of
    // HasPendingWrite(), which the connection calls once per stream on every IO
    // iteration (PickWritableStreamLocked -> the next stream with data). They
    // stay guarded by writeMu_ like the rest of the write state, but being
    // atomic lets that scan read the live values without taking one mutex per
    // stream. Relaxed is enough: a stale read only makes the scan look again on
    // the next Drive(), and every append is followed by a WakeUpOnData().
    std::atomic<uint64_t> sentOffset_{0};  // next byte to hand to ngtcp2
    std::atomic<uint64_t> tailOffset_{0};  // end of all appended data
    void AppendWriteLocked(const uint8_t* p, size_t n);
    void DropAckedLocked();

    // Backpressure cap on unacknowledged bytes: an unbounded sender would
    // pile up hundreds of MB while the peer's cwnd recovers (or a lossy path
    // keeps data in flight). Write() blocks above this; the ack callback
    // wakes it once the level drops back below the cap.
    //
    // It is a per-stream ceiling, so it multiplies by the number of uploads in
    // flight - 4MiB against a ~107-flow engine is 400MB of worst case, which is
    // why this is the number to reach for first if upload memory ever shows up.
    // 4MiB is still 2x the bandwidth-delay product the value was sized for
    // (100Mbps x 166ms ~ 2MB), and the uplink on an asymmetric line is a
    // fraction of that.
    static constexpr size_t kMaxWriteBuf = 4 * 1024 * 1024;

    bool writeClosed_ = false;
    std::atomic<bool> finPending_{false};  // FIN queued but not yet in a packet

    // Backpressure evidence for the TX-limit diagnostics (HY2_TXLIMIT_DIAG):
    // how often Write() parked on kMaxWriteBuf and for how long. Read and
    // summed by Ngtcp2Connection::PrintTxLimitLine.
    std::atomic<uint64_t> writeBlockedCount_{0};
    std::atomic<uint64_t> writeBlockedNs_{0};

    bool closed_ = false;

    MonoTime readDeadline_{};
    MonoTime writeDeadline_{};

    // Synchronization for blocking Read when buffer is empty
    std::condition_variable readCv_;
    std::condition_variable writeCv_;
};

} // namespace hy2::quic_backend
