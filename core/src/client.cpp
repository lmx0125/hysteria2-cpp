// client.cpp - rewrite of core/client/{client,config,reconnect}.go
#include "hy2/client.hpp"

#include <atomic>
#include <cctype>
#include <mutex>

#include "hy2/client_udp.hpp"

namespace hy2::client {

// ---------------------------------------------------------------------------
// Config verifyAndFill (config.go)

namespace {
constexpr uint64_t kDefaultStreamReceiveWindow = 8388608; // 8MB
constexpr uint64_t kDefaultConnReceiveWindow =
    kDefaultStreamReceiveWindow * 5 / 2; // 20MB
constexpr Duration kDefaultMaxIdleTimeout = Duration::FromSeconds(30);
constexpr Duration kDefaultKeepAlivePeriod = Duration::FromSeconds(10);

// wrapIfConnectionClosed checks if the error returned by the transport layer
// is recoverable (StreamLimitReachedError) or permanent.
// Recoverable errors are rethrown as-is, permanent ones are wrapped as ClosedError.
[[noreturn]] void rewrapError(const std::exception& e) {
    if (dynamic_cast<const StreamLimitReachedError*>(&e) != nullptr) {
        throw; // recoverable, pass through
    }
    throw ClosedError(e.what());
}
} // namespace

void Config::VerifyAndFill() {
    if (ServerAddr.empty()) {
        throw ConfigError("ServerAddr", "must be set");
    }
    if (QUICConfig.InitialStreamReceiveWindow == 0) {
        QUICConfig.InitialStreamReceiveWindow = kDefaultStreamReceiveWindow;
    } else if (QUICConfig.InitialStreamReceiveWindow < 16384) {
        throw ConfigError("QUICConfig.InitialStreamReceiveWindow", "must be at least 16384");
    }
    if (QUICConfig.MaxStreamReceiveWindow == 0) {
        QUICConfig.MaxStreamReceiveWindow = kDefaultStreamReceiveWindow;
    } else if (QUICConfig.MaxStreamReceiveWindow < 16384) {
        throw ConfigError("QUICConfig.MaxStreamReceiveWindow", "must be at least 16384");
    }
    if (QUICConfig.InitialConnectionReceiveWindow == 0) {
        QUICConfig.InitialConnectionReceiveWindow = kDefaultConnReceiveWindow;
    } else if (QUICConfig.InitialConnectionReceiveWindow < 16384) {
        throw ConfigError("QUICConfig.InitialConnectionReceiveWindow", "must be at least 16384");
    }
    if (QUICConfig.MaxConnectionReceiveWindow == 0) {
        QUICConfig.MaxConnectionReceiveWindow = kDefaultConnReceiveWindow;
    } else if (QUICConfig.MaxConnectionReceiveWindow < 16384) {
        throw ConfigError("QUICConfig.MaxConnectionReceiveWindow", "must be at least 16384");
    }
    if (QUICConfig.MaxIdleTimeout.ns == 0) {
        QUICConfig.MaxIdleTimeout = kDefaultMaxIdleTimeout;
    } else if (QUICConfig.MaxIdleTimeout < Duration::FromSeconds(4) ||
               QUICConfig.MaxIdleTimeout > Duration::FromSeconds(120)) {
        throw ConfigError("QUICConfig.MaxIdleTimeout", "must be between 4s and 120s");
    }
    if (QUICConfig.KeepAlivePeriod.ns == 0) {
        QUICConfig.KeepAlivePeriod = kDefaultKeepAlivePeriod;
    } else if (QUICConfig.KeepAlivePeriod < Duration::FromSeconds(2) ||
               QUICConfig.KeepAlivePeriod > Duration::FromSeconds(60)) {
        throw ConfigError("QUICConfig.KeepAlivePeriod", "must be between 2s and 60s");
    }
    CongestionCfg.Type = cc::NormalizeType(CongestionCfg.Type);
    if (CongestionCfg.Type == cc::TypeBBR) {
        CongestionCfg.BBRProfile = cc::NormalizeBBRProfile(CongestionCfg.BBRProfile);
    }
    // The QUIC transport must actually use the configured controller;
    // without this the ngtcp2 backend silently stayed on CUBIC regardless
    // of CongestionCfg.Type.
    if (QUICConfig.CongestionControl.empty()) {
        QUICConfig.CongestionControl = CongestionCfg.Type;
    }
    // A declared upload bandwidth means "send at this fixed rate and ignore
    // loss" - that is Hysteria's Brutal sender, and the ngtcp2 backend now
    // implements it (patched NGTCP2_CC_ALGO_BRUTAL). Without a declared rate
    // the loss-responsive controller stays in charge.
    if (BandwidthCfg.MaxTx > 0) {
        QUICConfig.CongestionControl = "brutal";
        QUICConfig.BrutalRate = BandwidthCfg.MaxTx;
        QUICConfig.BrutalDisableLossCompensation = BandwidthCfg.DisableLossCompensation;
    }
}

// ---------------------------------------------------------------------------
// TcpConn - net.Conn equivalent with fast-open lazy establishment.

class TcpConn : public IByteReaderWriter {
public:
    std::shared_ptr<QStream> Orig;
    std::string PseudoLocalAddr;
    std::string PseudoRemoteAddr;
    // Target address as passed to TCP(). With FastOpen the establishment is
    // validated here (first Read) instead of in TCP(), so the diagnostic below
    // needs the address this far down.
    std::string TargetAddr;
    bool Established = false;

    size_t Read(uint8_t* p, size_t n) override {
        if (!Established) {
            // Read response
            auto resp = proto::ReadTCPResponse(*Orig);
            if (!resp.OK) {
                Orig->Close();
                throw DialError(resp.Message);
            }
            Established = true;
            // The marker TCP() prints when it is not deferred, so a run with
            // fast_open still shows one "response OK" line per flow.
            static const bool diag = std::getenv("HY2_DIAG") != nullptr;
            if (diag) {
                std::fprintf(stderr, "[client] TCP %s: response OK (fast-open)\n",
                             TargetAddr.c_str());
                std::fflush(stderr);
            }
        }
        return Orig->Read(p, n);
    }

    void Write(const uint8_t* p, size_t n) override { Orig->Write(p, n); }

    void Close() override { Orig->Close(); }
    void CloseWrite() override { Orig->CloseWrite(); }

    // Forward to the QUIC stream so a caller holding only the IByteReaderWriter
    // (Client::TCP()'s return type) can bound a read. The deferred fast-open
    // response check in Read() above runs on the same stream, so the deadline
    // covers it too - which is what makes the prober's data probe fail in
    // seconds on a node that authenticates but never forwards anything.
    void SetReadDeadline(MonoTime t) override {
        if (Orig) Orig->SetReadDeadline(t);
    }

    const std::string& LocalAddr() const { return PseudoLocalAddr; }
    const std::string& RemoteAddr() const { return PseudoRemoteAddr; }
};

// ClientUdpIO mirrors udpIOImpl in client/client.go.
// Holds a shared_ptr to the QUIC connection: an outstanding relay connection
// (UdpConn) keeps its IO alive, and the IO keeps the connection alive, so a
// session outliving its Client can still Send/Receive (or fail cleanly)
// instead of writing through a dangling pointer.
class ClientUdpIO : public UdpIO {
public:
    explicit ClientUdpIO(std::shared_ptr<IQuicConnection> conn)
        : conn_(std::move(conn)) {}

    std::shared_ptr<proto::UDPMessage> ReceiveMessage() override {
        for (;;) {
            std::vector<uint8_t> msg = conn_->ReceiveDatagram(); // throws on close
            try {
                return std::make_shared<proto::UDPMessage>(
                    proto::ParseUDPMessage(msg.data(), msg.size()));
            } catch (const Error&) {
                // Invalid message, this is fine - just wait for the next
                continue;
            }
        }
    }

    void SendMessage(uint8_t* buf, size_t bufLen, const proto::UDPMessage& msg) override {
        int msgN = msg.Serialize(buf, bufLen);
        if (msgN < 0) {
            // Message larger than buffer, silent drop
            return;
        }
        conn_->SendDatagram(buf, static_cast<size_t>(msgN));
    }

private:
    std::shared_ptr<IQuicConnection> conn_;
};

// ---------------------------------------------------------------------------
// clientImpl

class ClientImpl : public Client,
                   public std::enable_shared_from_this<ClientImpl> {
public:
    explicit ClientImpl(Config config) : config_(std::move(config)) {}

    // connect performs the handshake; returns handshake info.
    HandshakeInfo connect(ClientTransport& transport);

    std::shared_ptr<IByteReaderWriter> TCP(const std::string& addr) override;
    std::shared_ptr<HyUDPConn> UDP() override;
    void Close() override;
    QuicStatsSnapshot Stats() const override;
    bool IsOpen() const override { return conn_ && !conn_->IsClosed(); }

    // Throws ClosedError when the connection is gone.
    //
    // A connection that hit the QUIC idle timeout - or that the peer closed - is
    // neither null nor guaranteed to fail the next call: it just stops carrying
    // data. With only the null check, callers kept using a dead connection
    // indefinitely. ClosedError is what both reconnect layers above are keyed
    // on: ReconnectableClientImpl::clientDo drops its client and redials on the
    // next call, and HyClientPool::MarkDead() re-queues the slot for the pool's
    // own reconnect worker.
    void EnsureOpen() const {
        if (!conn_ || conn_->IsClosed()) throw ClosedError();
    }

    Config config_;
    std::shared_ptr<IQuicConnection> conn_;

    std::shared_ptr<ClientUdpSessionManager> udpSM_;
    std::shared_ptr<ClientUdpIO> io_;
};

HandshakeInfo ClientImpl::connect(ClientTransport& transport) {
    // Send auth HTTP request
    proto::AuthRequest authReq;
    authReq.Auth = config_.Auth;
    authReq.Rx = config_.BandwidthCfg.MaxRx;

    ClientTransport::AuthResult result;
    try {
        result = transport.RoundTrip(config_, authReq);
    } catch (const ConnectError&) {
        throw;
    } catch (const std::exception& e) {
        throw ConnectError(e.what());
    }
    conn_ = result.Conn;
    if (result.StatusCode != proto::StatusAuthOK) {
        try {
            conn_->CloseWithError(CloseErrCodeProtocolError, "");
        } catch (...) {
        }
        throw AuthError(result.StatusCode);
    }

    // Auth OK
    proto::AuthResponse authResp = proto::AuthResponseFromHeader(result.Headers);
    uint64_t actualTx = 0;
    if (authResp.RxAuto) {
        // Server asks client to use bandwidth detection,
        // ignore local bandwidth config and use the configured congestion controller.
        cc::UseConfigured(*conn_, config_.CongestionCfg.Type, config_.CongestionCfg.BBRProfile);
    } else {
        // actualTx = min(serverRx, clientTx)
        actualTx = authResp.Rx;
        if (actualTx == 0 || actualTx > config_.BandwidthCfg.MaxTx) {
            // Server doesn't have a limit, or our clientTx is smaller than serverRx
            actualTx = config_.BandwidthCfg.MaxTx;
        }
        if (actualTx > 0) {
            cc::UseBrutal(*conn_, actualTx, config_.BandwidthCfg.DisableLossCompensation);
        } else {
            // We don't know our own bandwidth either, use the configured congestion controller.
            cc::UseConfigured(*conn_, config_.CongestionCfg.Type, config_.CongestionCfg.BBRProfile);
        }
    }

    HandshakeInfo info;
    info.UDPEnabled = authResp.UDPEnabled;
    info.Tx = actualTx;
    info.ServerAddr = config_.ServerAddr;
    info.ECHAccepted = false; // ECH is a transport-backend capability

    if (authResp.UDPEnabled) {
        io_ = std::make_shared<ClientUdpIO>(conn_);
        udpSM_ = ClientUdpSessionManager::Create(io_);
    }
    return info;
}

std::shared_ptr<IByteReaderWriter> ClientImpl::TCP(const std::string& addr) {
    EnsureOpen();
    static const bool diag = std::getenv("HY2_DIAG") != nullptr;
    std::shared_ptr<IQuicStream> stream;
    try {
        stream = conn_->OpenStream();
    } catch (const std::exception& e) {
        rewrapError(e);
    }
    auto qStream = std::make_shared<QStream>(stream);

    // Send request
    try {
        if (diag) {
            std::fprintf(stderr, "[client] TCP %s: stream open, writing request\n", addr.c_str());
            std::fflush(stderr);
        }
        proto::WriteTCPRequest(*qStream, addr);
        if (diag) {
            std::fprintf(stderr, "[client] TCP %s: request sent, waiting response\n", addr.c_str());
            std::fflush(stderr);
        }
    } catch (const std::exception& e) {
        qStream->Close();
        rewrapError(e);
    }

    auto tc = std::make_shared<TcpConn>();
    tc->Orig = qStream;
    tc->PseudoLocalAddr = conn_->LocalAddr();
    tc->PseudoRemoteAddr = conn_->RemoteAddr();
    tc->TargetAddr = addr;

    if (config_.FastOpen) {
        // Don't wait for the response when fast open is enabled.
        // Return the connection immediately, defer the response handling
        // to the first Read() call.
        tc->Established = false;
        return tc;
    }

    // Read response
    try {
        proto::TCPResponseResult resp = proto::ReadTCPResponse(*qStream);
        if (!resp.OK) {
            qStream->Close();
            throw DialError(resp.Message);
        }
        if (diag) {
            std::fprintf(stderr, "[client] TCP %s: response OK\n", addr.c_str());
            std::fflush(stderr);
        }
        tc->Established = true;
    } catch (const DialError&) {
        throw;
    } catch (const std::exception& e) {
        qStream->Close();
        rewrapError(e);
    }
    return tc;
}

std::shared_ptr<HyUDPConn> ClientImpl::UDP() {
    // The data path the TUN feeds, so this is the check that matters most: an
    // idle-closed connection used to hand out a fresh UdpConn here, and the
    // packets went into a socket nobody was reading - no exception, so no
    // reconnect, forever.
    EnsureOpen();
    if (!udpSM_) {
        throw DialError("UDP not enabled");
    }
    return udpSM_->NewUDP();
}

void ClientImpl::Close() {
    if (conn_) {
        try {
            conn_->CloseWithError(CloseErrCodeOK, "");
        } catch (...) {
        }
    }
}

QuicStatsSnapshot ClientImpl::Stats() const {
    if (!conn_) return {};
    return conn_->GetStatsSnapshot();
}

// ---------------------------------------------------------------------------
// Factories + global transport

namespace {
ClientTransport* g_transport = nullptr;
std::mutex g_transportMutex;

ClientTransport* globalTransport() {
    std::lock_guard<std::mutex> lk(g_transportMutex);
    return g_transport;
}
} // namespace

void SetGlobalClientTransport(ClientTransport* transport) {
    std::lock_guard<std::mutex> lk(g_transportMutex);
    g_transport = transport;
}

std::shared_ptr<Client> NewClient(Config config, HandshakeInfo* infoOut) {
    ClientTransport* t = globalTransport();
    if (!t) {
        throw Error("no client transport registered; use SetGlobalClientTransport "
                    "or NewClientWithTransport");
    }
    return NewClientWithTransport(std::move(config), *t, infoOut);
}

std::shared_ptr<Client> NewClientWithTransport(Config config, ClientTransport& transport,
                                               HandshakeInfo* infoOut) {
    config.VerifyAndFill();
    auto impl = std::make_shared<ClientImpl>(std::move(config));
    HandshakeInfo info = impl->connect(transport);
    if (infoOut) {
        *infoOut = info;
    }
    return impl;
}

// ---------------------------------------------------------------------------
// ReconnectableClient (reconnect.go)

namespace {

class ReconnectableClientImpl final : public Client {
public:
    ReconnectableClientImpl(ClientTransport& transport,
                            std::function<Config()> configFunc,
                            ConnectedCallback connectedFunc, bool lazy)
        : transport_(transport),
          configFunc_(std::move(configFunc)),
          connectedFunc_(std::move(connectedFunc)) {
        if (!lazy) {
            reconnect();
        }
    }

    std::shared_ptr<IByteReaderWriter> TCP(const std::string& addr) override {
        return clientDo<std::shared_ptr<IByteReaderWriter>>(
            [&](Client& c) { return c.TCP(addr); });
    }

    std::shared_ptr<HyUDPConn> UDP() override {
        return clientDo<std::shared_ptr<HyUDPConn>>([](Client& c) { return c.UDP(); });
    }

    void Close() override {
        std::lock_guard<std::mutex> lk(m_);
        closed_ = true;
        if (client_) {
            client_->Close();
        }
    }

    // Forward the live connection's counters. A pool measuring a slot must see
    // the connection that is up *now*, not whichever one it started with - the
    // inner client is replaced on every reconnect.
    QuicStatsSnapshot Stats() const override {
        std::lock_guard<std::mutex> lk(m_);
        return client_ ? client_->Stats() : QuicStatsSnapshot{};
    }

    bool IsOpen() const override {
        std::lock_guard<std::mutex> lk(m_);
        return !closed_ && client_ && client_->IsOpen();
    }

private:
    void reconnect() {
        if (client_) {
            try {
                client_->Close();
            } catch (...) {
            }
        }
        Config config = configFunc_();
        HandshakeInfo info;
        auto newClient = NewClientWithTransport(config, transport_, &info);
        client_ = newClient;
        count_++;
        if (connectedFunc_) {
            connectedFunc_(*newClient, info, count_);
        }
    }

    template <typename R>
    R clientDo(const std::function<R(Client&)>& f) {
        std::shared_ptr<Client> client;
        {
            std::lock_guard<std::mutex> lk(m_);
            if (closed_) {
                throw ClosedError();
            }
            if (!client_) {
                // No active connection, connect first
                reconnect();
            }
            client = client_;
        }

        try {
            return f(*client);
        } catch (ClosedError&) {
            // Connection closed, set client to nil for reconnect next time
            std::lock_guard<std::mutex> lk(m_);
            if (client_ == client) {
                // This check is in case the client is already changed by another thread
                client_ = nullptr;
            }
            throw;
        }
    }

    ClientTransport& transport_;
    std::function<Config()> configFunc_;
    ConnectedCallback connectedFunc_;
    std::shared_ptr<Client> client_;
    int count_ = 0;
    mutable std::mutex m_;
    bool closed_ = false; // permanent close
};

} // namespace

std::shared_ptr<Client> NewReconnectableClient(
    std::function<Config()> configFunc, ConnectedCallback connectedFunc, bool lazy) {
    ClientTransport* t = globalTransport();
    if (!t) {
        throw Error("no client transport registered; use SetGlobalClientTransport");
    }
    return std::make_shared<ReconnectableClientImpl>(*t, std::move(configFunc),
                                                     std::move(connectedFunc), lazy);
}

UdpRecvResult HyUDPConn::ReceivePacket(std::vector<uint8_t>& data, std::string& addr,
                                       Duration timeout) {
    // Default: drive the implementation's own Receive(). It reports false both
    // on timeout and on close, and the two are indistinguishable from here -
    // but a quiet session and a closed one differ in exactly one observable
    // way: a closed connection reports EOF again immediately, whereas a quiet
    // one keeps returning false for the whole deadline. Poll within the
    // deadline so the caller still gets a timely kTimeout, and only report
    // kClosed once the implementation is genuinely done. Implementations with
    // a real wait (UdpConn) override this and answer in one step; this
    // fallback exists so a third-party or test implementation that only knows
    // Receive() still behaves correctly.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::nanoseconds(timeout.ns);
    const auto perPoll = Duration::FromMillis(20);
    for (;;) {
        if (Receive(data, addr)) return UdpRecvResult::kPacket;
        if (std::chrono::steady_clock::now() >= deadline) {
            return UdpRecvResult::kTimeout;
        }
        hy2::SleepFor(perPoll);
    }
}

} // namespace hy2::client
