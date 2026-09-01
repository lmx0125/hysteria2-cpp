// server.hpp - Hysteria 2 core server. Rewrite of core/server/{server,config}.go.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "hy2/congestion.hpp"
#include "hy2/congestion_factory.hpp"
#include "hy2/copy.hpp"
#include "hy2/protocol.hpp"
#include "hy2/qstream.hpp"
#include "hy2/quic.hpp"
#include "hy2/quic_config.hpp"
#include "hy2/server_udp.hpp"
#include "hy2/varint.hpp"
#include "hy2/server_iface.hpp"

namespace hy2::server {

constexpr uint64_t CloseErrCodeOK = 0x100;                  // HTTP3 ErrCodeNoError
constexpr uint64_t CloseErrCodeTrafficLimitReached = 0x107; // HTTP3 ErrCodeExcessiveLoad
constexpr uint64_t CloseErrCodeProtocolError = 0x101;       // HTTP3 ErrCodeGeneralProtocolError

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

class Server;

struct Config {
    TlsServerConfig TLSConfig;
    QuicConfig QUICConfig;

    // Transport: the underlying packet conn is owned by the QUIC backend.
    // For tests, a listener can be injected directly via NewServerWithListener.
    bool HasConn = false;

    IRequestHook* RequestHookPtr = nullptr;
    Outbound* OutboundPtr = nullptr;
    CongestionConfig CongestionCfg;
    BandwidthConfig BandwidthCfg;
    bool IgnoreClientBandwidth = false;
    bool DisableUDP = false;
    Duration UDPIdleTimeout{};
    Authenticator* AuthenticatorPtr = nullptr;
    EventLogger* EventLoggerPtr = nullptr;
    ITrafficLogger* TrafficLoggerPtr = nullptr;
    IHttpHandler* MasqHandlerPtr = nullptr;

    // fill fills defaults and validates. Mirrors (*Config).fill().
    // Throws ConfigError on invalid input.
    void Fill();
};

// ---------------------------------------------------------------------------
// Server

class Server {
public:
    virtual ~Server() = default;
    // Serve blocks accepting connections; throws/returns on fatal error.
    //
    // LIFETIME CONTRACT: Serve() runs on the caller's thread and references
    // the Server for its whole duration. The caller must ensure Serve() has
    // returned before destroying the Server (Close() makes Accept return
    // promptly). Per-connection workers are owned and joined by the Server
    // itself; handler threads additionally share ownership of the config,
    // so they are safe even if the Server dies first.
    virtual void Serve() = 0;
    virtual void Close() = 0;
};

// QUIC backend factory: creates the QUIC listener for a server config.
using QuicBackendFactory =
    std::function<std::unique_ptr<IQuicListener>(const Config&)>;

// Registers the global transport backend used by NewServer (e.g. an
// OpenSSL/MsQuic based implementation). Not owned; must outlive usage.
void SetGlobalQuicBackend(QuicBackendFactory factory);

// NewServer validates the config and builds a server using the registered
// global backend. Throws when no backend has been registered.
std::unique_ptr<Server> NewServer(Config config);

// NewServerWithListener builds a server over an externally supplied QUIC
// listener (used by tests and custom transports). Takes ownership.
std::unique_ptr<Server> NewServerWithListener(Config config,
                                              std::unique_ptr<IQuicListener> listener);

// ---------------------------------------------------------------------------
// ServerImpl worker introspection (for tests / monitoring)
//
// The concrete Server tracks its per-connection worker threads so Close()
// can shut them down gracefully: it closes the listener, force-closes every
// live connection, then joins all workers. Access via dynamic_cast on the
// Server pointer, or use these free functions:
size_t ServerActiveWorkers(Server& s); // number of tracked, unfinished workers
void ServerWaitWorkersIdle(Server& s, int timeoutMs);
std::unique_ptr<Server> NewServerWithListener(Config config,
                                              std::unique_ptr<IQuicListener> listener);

// ---------------------------------------------------------------------------
// H3sHandler - per-connection protocol logic (auth + proxying).
//
// A real HTTP/3 backend drives this class: it parses HTTP/3 requests and
// calls ServeHTTP; it peeks stream frame types and calls ProxyStreamHijacker.
// The class itself contains all hysteria protocol semantics, so it can be
// exercised directly (and is, by the tests).
//
// Lifetime: inherits enable_shared_from_this - detached worker threads
// (handleTCPRequest / UDP session manager) capture shared_from_this(), and
// the handler owns a shared_ptr to its QUIC connection, mirroring the
// reachability guarantees Go's GC provides for h3sHandler.
class H3sHandler : public std::enable_shared_from_this<H3sHandler> {
public:
    // Takes shared ownership of the config: worker threads spawned by the
    // handler may outlive the Server object that produced the config
    // (mirroring Go, where goroutines keep the referenced state reachable).
    H3sHandler(std::shared_ptr<const Config> config, std::shared_ptr<IQuicConnection> conn);

    // Convenience overload for callers that hold Config as a value/lvalue
    // whose lifetime they guarantee outlives every connection (tests, embedders).
    explicit H3sHandler(const Config& config, std::shared_ptr<IQuicConnection> conn);

    // Port of h3sHandler.ServeHTTP.
    void ServeHTTP(HttpResponseWriter& w, const HttpRequest& r);

    // Port of h3sHandler.ProxyStreamHijacker. Returns true if the frame was
    // handled as a TCP request (ownership of stream retained).
    bool ProxyStreamHijacker(uint64_t frameType, std::shared_ptr<IHyStream> stream);

    bool Authenticated() const { return authenticated_.load(std::memory_order_acquire); }
    const std::string& AuthID() const { return authID_; }

private:
    void handleTCPRequest(std::shared_ptr<IHyStream> stream);
    void masqHandler(HttpResponseWriter& w, const HttpRequest& r);
    void startUdpSessionManager();

    std::shared_ptr<const Config> configPtr_;
    const Config& config_;
    // Owned connection: keeps the QUIC connection alive for as long as any
    // worker thread (including the UDP session manager) may still use it.
    std::shared_ptr<IQuicConnection> connPtr_;
    IQuicConnection& conn_;

    // Written under authMutex_ in ServeHTTP; read lock-free in
    // ProxyStreamHijacker - hence atomic (release/acquire).
    std::atomic<bool> authenticated_{false};
    std::mutex authMutex_;
    std::string authID_;
    uint32_t connID_ = 0; // a random id for dump streams

    // Only set after authentication (and when UDP is enabled).
    std::shared_ptr<UdpSessionManager> udpSM_;
    std::mutex udpSMMutex_; // protects lazy creation

    friend class UdpIOImpl;
};

} // namespace hy2::server
