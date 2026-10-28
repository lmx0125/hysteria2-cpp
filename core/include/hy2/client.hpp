// client.hpp - Hysteria 2 core client. Rewrite of core/client/*.go.
#pragma once

#include <functional>
#include <memory>
#include <string>

#include "hy2/congestion_factory.hpp"
#include "hy2/io.hpp"
#include "hy2/protocol.hpp"
#include "hy2/qstream.hpp"
#include "hy2/quic.hpp"
#include "hy2/quic_config.hpp"

namespace hy2::client {

constexpr uint64_t CloseErrCodeOK = 0x100;            // HTTP3 ErrCodeNoError
constexpr uint64_t CloseErrCodeProtocolError = 0x101; // HTTP3 ErrCodeGeneralProtocolError

// ---------------------------------------------------------------------------
// Config (config.go)

struct BandwidthConfig {
    uint64_t MaxTx = 0;
    uint64_t MaxRx = 0;
    bool DisableLossCompensation = false;
};

struct CongestionConfig {
    std::string Type;      // "bbr" or "reno"
    std::string BBRProfile;
};

class Client;

struct Config {
    std::string ServerAddr; // host:port
    std::string Auth;
    TlsClientConfig TLSConfig;
    QuicConfig QUICConfig;
    CongestionConfig CongestionCfg;
    BandwidthConfig BandwidthCfg;
    bool FastOpen = false;

    // verifyAndFill fills defaults and validates. Mirrors (*Config).verifyAndFill().
    void VerifyAndFill();
};

// ClientTransport performs the connection + HTTP/3 auth round trip.
// A real backend implements this over QUIC+HTTP/3; tests use mocks.
class ClientTransport {
public:
    virtual ~ClientTransport() = default;

    struct AuthResult {
        std::shared_ptr<IQuicConnection> Conn;
        int StatusCode = 0;
        proto::HeaderMap Headers;
    };

    // Performs the handshake: dials the server, sends the auth request,
    // returns the connection plus response status/headers. Throws ConnectError
    // wrappers on failure (the caller maps non-233 statuses to AuthError).
    virtual AuthResult RoundTrip(const Config& cfg, const proto::AuthRequest& req) = 0;
};

// Registers the global transport used by NewClient (real QUIC backend).
void SetGlobalClientTransport(ClientTransport* transport);

// ---------------------------------------------------------------------------
// HyUDPConn - client-side UDP relay connection.

// Outcome of a timed UDP receive. A UDP relay session is idle most of the
// time (a DNS lookup, a QUIC handshake, a game's keepalive), so "nothing
// arrived yet" has to be distinguishable from "the session is over" -
// treating the former as the latter tears down a perfectly good relay after
// one quiet poll.
enum class UdpRecvResult {
    kPacket,  // data/addr were filled in
    kTimeout, // nothing arrived within the deadline; the conn is still good
    kClosed,  // the session ended (or the transport is gone)
};

class HyUDPConn {
public:
    virtual ~HyUDPConn() = default;
    // Receive blocks until a packet arrives. Returns false when closed (EOF)
    // OR when the internal wait elapsed with nothing to deliver - callers that
    // loop on it MUST tolerate spurious false returns (see ReceivePacket).
    virtual bool Receive(std::vector<uint8_t>& data, std::string& addr) = 0;
    // ReceivePacket waits up to `timeout` for a datagram and reports which of
    // the three outcomes happened, so a quiet session is distinguishable from
    // a closed one. Defaulted in terms of Receive() with the requested
    // timeout, which keeps every existing implementation correct; an
    // implementation with a real condition variable (UdpConn) overrides it so
    // the wait is exact instead of quantised to its internal polling period.
    virtual UdpRecvResult ReceivePacket(std::vector<uint8_t>& data, std::string& addr,
                                        Duration timeout);
    // Test/diagnostic hook: the timeout the client-side implementation uses
    // when Receive() is called. 0 = the built-in default.
    virtual Duration ReceivePollTimeout() const { return Duration(0); }
    // Send sends a UDP packet to addr. Throws on error / fragments when needed.
    virtual void Send(const uint8_t* data, size_t n, const std::string& addr) = 0;
    virtual void Close() = 0;
};

// ---------------------------------------------------------------------------
// Client

class Client {
public:
    virtual ~Client() = default;
    // TCP opens a proxied TCP connection to addr ("host:port").
    // The returned stream carries payload bytes after handshake completion.
    virtual std::shared_ptr<IByteReaderWriter> TCP(const std::string& addr) = 0;
    virtual std::shared_ptr<HyUDPConn> UDP() = 0;
    virtual void Close() = 0;

    // Live counters for the connection behind this client, so a pool can tell
    // which of its connections is actually delivering. Defaulted: a client that
    // has no such notion (or a test double) reports zeros and the caller falls
    // back to its other inputs.
    virtual QuicStatsSnapshot Stats() const { return {}; }

    // Returns true if the underlying transport is currently open and usable.
    virtual bool IsOpen() const { return true; }
};

struct HandshakeInfo {
    bool UDPEnabled = false;
    uint64_t Tx = 0;          // 0 if using BBR
    std::string ServerAddr;
    bool ECHAccepted = false;
};

// NewClient verifies the config, connects and authenticates.
// Requires SetGlobalClientTransport (or use NewClientWithTransport).
std::shared_ptr<Client> NewClient(Config config, HandshakeInfo* infoOut = nullptr);

// NewClientWithTransport - dependency-injected variant (tests/custom transports).
std::shared_ptr<Client> NewClientWithTransport(Config config, ClientTransport& transport,
                                               HandshakeInfo* infoOut = nullptr);

// ---------------------------------------------------------------------------
// ReconnectableClient (reconnect.go)

using ConnectedCallback = std::function<void(Client&, const HandshakeInfo&, int)>;

// Creates a reconnectable client. If lazy is true, no connection is made
// until the first TCP()/UDP() call.
std::shared_ptr<Client> NewReconnectableClient(
    std::function<Config()> configFunc, ConnectedCallback connectedFunc = nullptr,
    bool lazy = true);

} // namespace hy2::client
