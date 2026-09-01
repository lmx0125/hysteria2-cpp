#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

#include <ngtcp2/ngtcp2.h>

#include "hy2/quic.hpp"

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
    void OnStreamData(const uint8_t* data, size_t len, bool fin);

    // Called by Ngtcp2Connection when the peer closes/resets this stream.
    void OnStreamClose(uint64_t appErrorCode);
    void OnStreamReset(uint64_t finalSize, uint64_t appErrorCode);

    // Called by Ngtcp2Connection when data is acked (write buffer drain).
    void OnAckedStreamData(uint64_t offset, uint64_t datalen);

    // Write-side plumbing used by Ngtcp2Connection::Drive():
    // Copies pending (unwritten) bytes into dst (up to cap) and reports
    // whether a FIN is pending, all under one writeMu_ acquisition.
    // Returns true if there was anything pending.
    bool CopyPendingWrite(uint8_t* dst, size_t cap, size_t* outLen, bool* outFin);
    bool HasPendingWrite() const;
    bool FinPending() const;
    void AdvanceWrite(size_t n);
    void ClearFinPending();
    // Mark the local write side finished (sends FIN).
    void SetFinPending();

    bool IsClosed() const;

private:
    Ngtcp2Stream(Ngtcp2Connection* conn, int64_t streamId);

    Ngtcp2Connection* conn_ = nullptr;
    int64_t streamId_ = 0;

    mutable std::mutex readMu_;
    std::vector<uint8_t> readBuf_;
    size_t readPos_ = 0;
    bool readEof_ = false;
    bool readClosed_ = false;

    mutable std::mutex writeMu_;
    // deque: Write appends at the back, Drive advances from the front.
    // A vector would memmove the whole remaining backlog on every
    // AdvanceWrite — O(buffer size) per packet, freezing the loop once
    // the backlog grows large.
    std::deque<uint8_t> writeBuf_;
    size_t writeAckedPos_ = 0;   // how much has been acked
    bool writeClosed_ = false;
    bool finPending_ = false;    // FIN queued but not yet written into a packet

    bool closed_ = false;

    MonoTime readDeadline_{};
    MonoTime writeDeadline_{};

    // Synchronization for blocking Read when buffer is empty
    std::condition_variable readCv_;
    std::condition_variable writeCv_;
};

} // namespace hy2::quic_backend
