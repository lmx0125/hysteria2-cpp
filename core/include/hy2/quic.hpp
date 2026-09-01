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
