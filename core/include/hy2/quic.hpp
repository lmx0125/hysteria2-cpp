// quic.hpp - QUIC transport abstractions.
//
// The original Go code depends on quic-go types (quic.Conn, quic.Stream,
// http3). For the C++ rewrite, these are expressed as interfaces so that:
//   1. All session/protocol logic is testable without a real network stack
//      (mirroring the Go unit tests which use mocks).
//   2. Any real QUIC implementation (OpenSSL 3.2+ SSL_QUIC_METHOD, MsQuic,
//      lsquic, ...) can be plugged in behind these interfaces without
//      touching protocol code. The wire format is defined by protocol.hpp
//      and PROTOCOL.md, not by this abstraction layer.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "hy2/common.hpp"
#include "hy2/congestion.hpp"
#include "hy2/error.hpp"
#include "hy2/io.hpp"

namespace hy2 {

// IQuicStream mirrors quic.Stream.
class IQuicStream : public IHyStream {
public:
    // Close closes only the write side in raw QUIC terms; use via QStream for
    // the combined semantics used throughout hysteria.
    using IHyStream::Close;
    void CloseWrite() override { Close(); }
};

// QuicStatsSnapshot is a backend-neutral view of one connection's counters,
// enough to tell how much a connection actually delivered and how much of what
// it sent was lost. A rate controller needs both: delivered bytes say whether a
// declared rate is being achieved, lost packets say whether it is being
// exceeded (a fixed-rate sender that overshoots a link loses packets instead of
// slowing down).
struct QuicStatsSnapshot {
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    uint64_t packetsSent = 0;
    uint64_t packetsReceived = 0;
    uint64_t packetsLost = 0;
    uint64_t streamsActive = 0;
    // Streams currently open on the connection. Distinct from streamsActive,
    // which counts only those with a write *pending* - data queued to send. A
    // pure download has nothing pending to write, so streamsActive reads zero
    // while the connection is in fact carrying every byte; anything asking "is
    // this connection carrying flows?" needs this one instead.
    uint64_t streamsOpen = 0;
    double smoothedRttMs = 0.0;
};

// IQuicConnection mirrors the subset of quic.Conn used by hysteria.
class IQuicConnection {
public:
    virtual ~IQuicConnection() = default;

    virtual std::shared_ptr<IQuicStream> OpenStream() = 0;
    // Opens a unidirectional stream (HTTP/3 control/qpack streams).
    // Returns nullptr when the backend does not support it (mocks).
    virtual std::shared_ptr<IQuicStream> OpenUniStream() { return nullptr; }
    virtual std::shared_ptr<IQuicStream> AcceptUniStream() { return nullptr; }
    virtual std::shared_ptr<IQuicStream> AcceptStream() = 0;
    // Timed accept: returns nullptr after timeoutMs if no stream arrives.
    virtual std::shared_ptr<IQuicStream> AcceptStreamFor(int /*timeoutMs*/) { return AcceptStream(); }

    // SendDatagram throws DatagramTooLargeError{maxDatagramPayloadSize}
    // when the message exceeds the peer's advertised datagram size
    // (mirrors quic.ErrDatagramTooLarge).
    virtual void SendDatagram(const uint8_t* p, size_t n) = 0;

    // ReceiveDatagram blocks until a datagram arrives; throws when closed.
    virtual std::vector<uint8_t> ReceiveDatagram() = 0;

    virtual void CloseWithError(uint64_t errorCode, const std::string& reason) = 0;

    // True once the connection reached a terminal state: the QUIC idle
    // timeout, a peer CONNECTION_CLOSE/draining, or an explicit local close.
    //
    // A connection can die with nobody noticing - the idle timeout is the usual
    // way, because an idle tunnel sends nothing that would reset it. Owners that
    // only react to I/O errors keep handing out such a connection and writing
    // into a socket nobody reads, so they need a way to ask. Default false keeps
    // backends and test doubles that have no such notion compiling.
    virtual bool IsClosed() const { return false; }

    // Counters for rate control. Defaulted so backends and test doubles that
    // keep no statistics stay compilable; a backend that returns nothing just
    // makes the controller fall back to its other inputs.
    virtual QuicStatsSnapshot GetStatsSnapshot() const { return {}; }

    virtual std::string LocalAddr() const = 0;
    virtual std::string RemoteAddr() const = 0;

    // Congestion control hook (mirrors conn.SetCongestionControl). May be a
    // no-op depending on the backend; kept so client/server logic can attach
    // BrutalSender/BBR exactly like the Go implementation does.
    virtual void SetCongestionControl(std::shared_ptr<cc::CongestionControl> cc) {
        congestion_ = std::move(cc);
    }
    std::shared_ptr<cc::CongestionControl> GetCongestionControl() const { return congestion_; }

protected:
    std::shared_ptr<cc::CongestionControl> congestion_;
};

// IQuicListener mirrors quic.Listener: accepts incoming connections.
class IQuicListener {
public:
    virtual ~IQuicListener() = default;
    // Accept blocks until a new connection arrives or the listener closes
    // (then returns nullptr).
    virtual std::shared_ptr<IQuicConnection> Accept() = 0;
    virtual void Close() = 0;
};

} // namespace hy2
