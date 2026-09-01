// server.cpp - Rewrite of core/server/server.go + config.go.
#include "hy2/server.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <thread>

namespace hy2::server {

// ---------------------------------------------------------------------------
// Config fill (config.go)

namespace {
constexpr uint64_t kDefaultStreamReceiveWindow = 8388608; // 8MB
constexpr uint64_t kDefaultConnReceiveWindow =
    kDefaultStreamReceiveWindow * 5 / 2; // 20MB
constexpr Duration kDefaultMaxIdleTimeout = Duration::FromSeconds(30);
constexpr int64_t kDefaultMaxIncomingStreams = 1024;
constexpr Duration kDefaultUDPIdleTimeout = Duration::FromSeconds(60);

std::string toLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
} // namespace

void Config::Fill() {
    if (TLSConfig.CertificatesPEM.empty()) {
        throw ConfigError("TLSConfig", "must set at least one of Certificates or GetCertificate");
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
    if (QUICConfig.MaxIncomingStreams == 0) {
        QUICConfig.MaxIncomingStreams = kDefaultMaxIncomingStreams;
    } else if (QUICConfig.MaxIncomingStreams < 8) {
        throw ConfigError("QUICConfig.MaxIncomingStreams", "must be at least 8");
    }
    // pmtud.DisablePathMTUDiscovery is false on all platforms we build for.
    CongestionCfg.Type = cc::NormalizeType(CongestionCfg.Type);
    if (CongestionCfg.Type == cc::TypeBBR) {
        CongestionCfg.BBRProfile = cc::NormalizeBBRProfile(CongestionCfg.BBRProfile);
    }
    if (!HasConn) {
        throw ConfigError("Conn", "must be set");
    }
    // Outbound defaults to a direct outbound when nil - the app layer wires it.
    if (BandwidthCfg.MaxTx != 0 && BandwidthCfg.MaxTx < 65536) {
        throw ConfigError("BandwidthConfig.MaxTx", "must be at least 65536");
    }
    if (BandwidthCfg.MaxRx != 0 && BandwidthCfg.MaxRx < 65536) {
        throw ConfigError("BandwidthConfig.MaxRx", "must be at least 65536");
    }
    if (UDPIdleTimeout.ns == 0) {
        UDPIdleTimeout = kDefaultUDPIdleTimeout;
    } else if (UDPIdleTimeout < Duration::FromSeconds(2) ||
               UDPIdleTimeout > Duration::FromSeconds(600)) {
        throw ConfigError("UDPIdleTimeout", "must be between 2s and 600s");
    }
    if (AuthenticatorPtr == nullptr) {
        throw ConfigError("Authenticator", "must be set");
    }
}

// ---------------------------------------------------------------------------
// udpIOImpl / udpEventLoggerImpl (server.go)
//
// Both hold shared_ptr<IQuicConnection>: they may outlive the handler that
// created them (the UDP manager run thread keeps them alive), so owning the
// connection is what prevents dangling references.

class UdpIOImpl : public UdpIO {
public:
    UdpIOImpl(std::shared_ptr<IQuicConnection> conn, std::string authID,
              ITrafficLogger* tl, IRequestHook* hook, Outbound* outbound)
        : conn_(std::move(conn)), authID_(std::move(authID)), tl_(tl), hook_(hook),
          outbound_(outbound) {}

    std::shared_ptr<proto::UDPMessage> ReceiveMessage() override {
        for (;;) {
            std::vector<uint8_t> msg = conn_->ReceiveDatagram(); // throws on close
            std::shared_ptr<proto::UDPMessage> udpMsg;
            try {
                udpMsg = std::make_shared<proto::UDPMessage>(
                    proto::ParseUDPMessage(msg.data(), msg.size()));
            } catch (const Error&) {
                // Invalid message, this is fine - just wait for the next
                continue;
            }
            if (tl_ != nullptr) {
                bool ok = tl_->LogTraffic(authID_, udpMsg->Data.size(), 0);
                if (!ok) {
                    // TrafficLogger requested to disconnect the client
                    conn_->CloseWithError(CloseErrCodeTrafficLimitReached, "");
                    throw ErrDisconnect();
                }
            }
            return udpMsg;
        }
    }

    void SendMessage(uint8_t* buf, size_t bufLen, const proto::UDPMessage& msg) override {
        if (tl_ != nullptr) {
            bool ok = tl_->LogTraffic(authID_, 0, msg.Data.size());
            if (!ok) {
                // TrafficLogger requested to disconnect the client
                conn_->CloseWithError(CloseErrCodeTrafficLimitReached, "");
                throw ErrDisconnect();
            }
        }
        int msgN = msg.Serialize(buf, bufLen);
        if (msgN < 0) {
            // Message larger than buffer, silent drop
            return;
        }
        conn_->SendDatagram(buf, static_cast<size_t>(msgN));
    }

    void Hook(std::vector<uint8_t>& data, std::string& reqAddr) override {
        if (hook_ != nullptr && hook_->Check(true, reqAddr)) {
            hook_->UDP(data, reqAddr);
        }
    }

    std::shared_ptr<IUdpConn> UDP(const std::string& reqAddr) override {
        return outbound_->UDP(reqAddr);
    }

    bool CheckUDP(const std::string& reqAddr) override {
        return outbound_->CheckUDP(reqAddr);
    }

private:
    std::shared_ptr<IQuicConnection> conn_;
    std::string authID_;
    ITrafficLogger* tl_;
    IRequestHook* hook_;
    Outbound* outbound_;
};

namespace {
class UdpEventLoggerImpl : public UdpEventLogger {
public:
    UdpEventLoggerImpl(std::shared_ptr<IQuicConnection> conn, std::string authID,
                       EventLogger* el)
        : conn_(std::move(conn)), authID_(std::move(authID)), el_(el) {}

    void New(uint32_t sessionID, const std::string& reqAddr) override {
        if (el_) el_->UDPRequest(conn_->RemoteAddr(), authID_, sessionID, reqAddr);
    }

    void Close(uint32_t sessionID, const std::string& err) override {
        if (el_) el_->UDPError(conn_->RemoteAddr(), authID_, sessionID, err);
    }

private:
    std::shared_ptr<IQuicConnection> conn_;
    std::string authID_;
    EventLogger* el_;
};
} // namespace

// ---------------------------------------------------------------------------
// H3sHandler

H3sHandler::H3sHandler(std::shared_ptr<const Config> config,
                       std::shared_ptr<IQuicConnection> conn)
    : configPtr_(std::move(config)), config_(*configPtr_),
      connPtr_(std::move(conn)), conn_(*connPtr_), connID_(RandomUint32()) {}

H3sHandler::H3sHandler(const Config& config, std::shared_ptr<IQuicConnection> conn)
    : H3sHandler(std::make_shared<const Config>(config), std::move(conn)) {}

void H3sHandler::ServeHTTP(HttpResponseWriter& w, const HttpRequest& r) {
    auto writeAuthOK = [&]() {
        proto::AuthResponseToHeader(w.Header(), proto::AuthResponse{
                                                   !config_.DisableUDP,
                                                   config_.BandwidthCfg.MaxRx,
                                                   config_.IgnoreClientBandwidth,
                                               });
        w.WriteHeader(proto::StatusAuthOK);
    };

    if (r.Method == "POST" && r.Host == proto::URLHost && r.Path == proto::URLPath) {
        std::lock_guard<std::mutex> lk(authMutex_);
        if (authenticated_.load(std::memory_order_relaxed)) {
            // Already authenticated
            writeAuthOK();
            return;
        }
        proto::AuthRequest authReq = proto::AuthRequestFromHeader(r.Header);
        uint64_t actualTx = authReq.Rx;
        std::string id;
        bool ok = config_.AuthenticatorPtr->Authenticate(conn_.RemoteAddr(), authReq.Auth, actualTx, id);
        if (ok) {
            // Set authenticated flag (release: publishes authID_ and the
            // congestion-control attachment to lock-free readers).
            authID_ = id;
            authenticated_.store(true, std::memory_order_release);
            if (config_.IgnoreClientBandwidth) {
                // Ignore client bandwidth and use the configured congestion controller.
                cc::UseConfigured(conn_, config_.CongestionCfg.Type, config_.CongestionCfg.BBRProfile);
                actualTx = 0;
            } else {
                // actualTx = min(serverTx, clientRx)
                if (config_.BandwidthCfg.MaxTx > 0 && actualTx > config_.BandwidthCfg.MaxTx) {
                    // We have a maxTx limit and the client is asking for more than that,
                    // return and use the limit instead
                    actualTx = config_.BandwidthCfg.MaxTx;
                }
                if (actualTx > 0) {
                    cc::UseBrutal(conn_, actualTx, config_.BandwidthCfg.DisableLossCompensation);
                } else {
                    // Client doesn't know its own bandwidth, use the configured congestion controller.
                    cc::UseConfigured(conn_, config_.CongestionCfg.Type, config_.CongestionCfg.BBRProfile);
                }
            }
            // Auth OK, send response
            writeAuthOK();
            // Call event logger
            if (config_.TrafficLoggerPtr != nullptr) {
                config_.TrafficLoggerPtr->LogOnlineState(id, true);
            }
            if (config_.EventLoggerPtr != nullptr) {
                config_.EventLoggerPtr->Connect(conn_.RemoteAddr(), id, actualTx);
            }
            // Initialize UDP session manager (if UDP is enabled)
            if (!config_.DisableUDP) {
                startUdpSessionManager();
            }
        } else {
            // Auth failed, pretend to be a normal HTTP server
            masqHandler(w, r);
        }
    } else {
        // Not an auth request, pretend to be a normal HTTP server
        masqHandler(w, r);
    }
}

void H3sHandler::startUdpSessionManager() {
    std::lock_guard<std::mutex> lk(udpSMMutex_);
    if (udpSM_) return; // only one manager per connection
    // io/el hold a shared_ptr to the connection, so they (and the session
    // manager thread) keep it alive independently of this handler.
    auto io = std::make_shared<UdpIOImpl>(connPtr_, authID_, config_.TrafficLoggerPtr,
                                          config_.RequestHookPtr, config_.OutboundPtr);
    auto el = std::make_shared<UdpEventLoggerImpl>(connPtr_, authID_, config_.EventLoggerPtr);
    udpSM_ = UdpSessionManager::Create(io, el, config_.UDPIdleTimeout);
}

bool H3sHandler::ProxyStreamHijacker(uint64_t frameType, std::shared_ptr<IHyStream> stream) {
    // Lock-free read of the auth flag (atomic acquire pairs with the
    // release store in ServeHTTP).
    if (!authenticated_.load(std::memory_order_acquire)) {
        return false;
    }

    switch (frameType) {
    case proto::FrameTypeTCPRequest: {
        // StreamDispatcher only peeks the frame type. Consume it so ReadTCPRequest
        // starts at address length, matching pre-upgrade StreamHijacker behavior.
        try {
            VarintRead(*stream);
        } catch (const std::exception&) {
            return false;
        }
        // Wraps the stream with QStream, which handles Close() properly.
        auto qStream =
            std::make_shared<QStream>(std::static_pointer_cast<IQuicStream>(stream));
        // Capture shared_from_this(): the worker thread keeps the handler
        // (and, through it, the connection) alive - mirrors Go where the
        // goroutine's receiver keeps *h3sHandler reachable for the GC.
        auto self = shared_from_this();
        std::thread([self, qStream]() { self->handleTCPRequest(qStream); }).detach();
        return true;
    }
    default:
        return false;
    }
}

void H3sHandler::handleTCPRequest(std::shared_ptr<IHyStream> stream) {
    ITrafficLogger* trafficLogger = config_.TrafficLoggerPtr;
    auto streamStats = std::make_shared<StreamStats>();
    streamStats->AuthID = authID_;
    streamStats->ConnID = connID_;
    streamStats->SetInitialTimeNow();
    streamStats->State.Store(StreamState::Initial);
    streamStats->LastActiveTime.Set(MonoTime::Now().ns);

    if (trafficLogger != nullptr) {
        trafficLogger->TraceStream(stream.get(), streamStats.get());
    }

    std::string firstErr;
    try {
        // Read request
        std::string reqAddr = proto::ReadTCPRequest(*stream);
        streamStats->ReqAddr.Store(reqAddr);

        // Call the hook if set
        std::vector<uint8_t> putback;
        bool hooked = false;
        if (config_.RequestHookPtr != nullptr) {
            hooked = config_.RequestHookPtr->Check(false, reqAddr);
            // When the hook is enabled, the server should always accept a connection
            // so that the client will send whatever request the hook wants to see.
            // This is essentially a server-side fast-open.
            if (hooked) {
                streamStats->State.Store(StreamState::Hooking);
                proto::WriteTCPResponse(*stream, true, "RequestHook enabled");
                putback = config_.RequestHookPtr->TCP(*stream, reqAddr);
                streamStats->setHookedReqAddr(reqAddr);
            }
        }

        // Log the event
        if (config_.EventLoggerPtr != nullptr) {
            config_.EventLoggerPtr->TCPRequest(conn_.RemoteAddr(), authID_, reqAddr);
        }

        // Dial target
        streamStats->State.Store(StreamState::Connecting);
        std::shared_ptr<IConn> tConn;
        try {
            tConn = config_.OutboundPtr->TCP(reqAddr);
        } catch (const std::exception& e) {
            if (!hooked) {
                proto::WriteTCPResponse(*stream, false, e.what());
            }
            stream->Close();
            // Log the error
            if (config_.EventLoggerPtr != nullptr) {
                config_.EventLoggerPtr->TCPError(conn_.RemoteAddr(), authID_, reqAddr, e.what());
            }
            if (trafficLogger != nullptr) trafficLogger->UntraceStream(stream.get());
            streamStats->State.Store(StreamState::Closed);
            return;
        }

        if (!hooked) {
            proto::WriteTCPResponse(*stream, true, "Connected");
        }
        streamStats->State.Store(StreamState::Established);

        // Put back the data if the hook requested
        if (!putback.empty()) {
            try {
                tConn->Write(putback.data(), putback.size());
                streamStats->Tx.fetch_add(putback.size());
            } catch (...) {
            }
        }

        // Start proxying
        auto sRw = std::static_pointer_cast<IByteReaderWriter>(stream);
        auto rRw = std::static_pointer_cast<IByteReaderWriter>(
            std::shared_ptr<IConn>(tConn));
        if (trafficLogger != nullptr) {
            firstErr = CopyTwoWayEx(authID_, sRw, rRw, trafficLogger, *streamStats);
        } else {
            // Use the fast path if no traffic logger is set
            firstErr = CopyTwoWay(sRw, rRw);
        }

        if (config_.EventLoggerPtr != nullptr) {
            config_.EventLoggerPtr->TCPError(conn_.RemoteAddr(), authID_, reqAddr, firstErr);
        }

        // Cleanup
        tConn->Close();
        stream->Close();

        // Disconnect the client if TrafficLogger requested
        if (firstErr == "traffic logger requested disconnect") {
            conn_.CloseWithError(CloseErrCodeTrafficLimitReached, "");
        }
    } catch (...) {
        try {
            stream->Close();
        } catch (...) {
        }
    }

    if (trafficLogger != nullptr) trafficLogger->UntraceStream(stream.get());
    streamStats->State.Store(StreamState::Closed);
}

void H3sHandler::masqHandler(HttpResponseWriter& w, const HttpRequest& r) {
    if (config_.MasqHandlerPtr != nullptr) {
        config_.MasqHandlerPtr->ServeHTTP(w, r);
    } else {
        // Return 404 for everything
        w.Header()["Content-Type"] = "text/plain; charset=utf-8";
        w.Header()["X-Content-Type-Options"] = "nosniff";
        w.WriteHeader(404);
        const char body[] = "404 page not found\n";
        w.Write(reinterpret_cast<const uint8_t*>(body), sizeof(body) - 1);
    }
}

// ---------------------------------------------------------------------------
// Server implementation

namespace {

class ServerImpl : public Server {
public:
    ServerImpl(Config config, std::unique_ptr<IQuicListener> listener)
        : configPtr_(std::make_shared<Config>(std::move(config))),
          listener_(std::move(listener)) {}

    ~ServerImpl() override { Close(); }

    void Serve() override {
        for (;;) {
            auto conn = listener_->Accept();
            if (!conn) {
                return; // listener closed
            }
            trackWorker(conn);
        }
    }

    void Close() override {
        bool expected = false;
        if (!closed_.compare_exchange_strong(expected, true)) {
            return; // already closed
        }
        listener_->Close();

        // Graceful shutdown (mirrors quic.Transport.Close killing all conns):
        // force-close every tracked connection so its handleClient loop exits,
        // then join all workers.
        std::vector<std::thread> toJoin;
        {
            std::lock_guard<std::mutex> lk(workersMutex_);
            for (auto& w : workers_) {
                if (auto conn = w.conn.lock()) {
                    try {
                        conn->CloseWithError(CloseErrCodeOK, "");
                    } catch (...) {
                    }
                }
            }
            toJoin.reserve(workers_.size());
            for (auto& w : workers_) {
                if (w.th.joinable()) {
                    toJoin.push_back(std::move(w.th));
                }
            }
            workers_.clear();
        }
        for (auto& t : toJoin) {
            t.join();
        }
    }

    size_t ActiveWorkers() {
        std::lock_guard<std::mutex> lk(workersMutex_);
        purgeLocked();
        return workers_.size();
    }

private:
    struct Worker {
        std::thread th;
        std::weak_ptr<IQuicConnection> conn;
        std::shared_ptr<std::atomic<bool>> done;
    };

    // Purges entries whose thread has finished. Joining an already-finished
    // thread returns immediately, so this is non-blocking.
    void purgeLocked() {
        for (auto it = workers_.begin(); it != workers_.end();) {
            if (it->done->load(std::memory_order_acquire) && it->th.joinable()) {
                it->th.join(); // immediate: thread already done
                it = workers_.erase(it);
            } else {
                ++it;
            }
        }
    }

    void trackWorker(std::shared_ptr<IQuicConnection> conn) {
        Worker w;
        w.conn = conn;
        w.done = std::make_shared<std::atomic<bool>>(false);
        auto* done = w.done.get();
        w.th = std::thread([this, conn, done] {
            try {
                handleClient(conn);
            } catch (...) {
                // No exception may escape a thread function (std::terminate).
            }
            done->store(true, std::memory_order_release);
        });
        std::lock_guard<std::mutex> lk(workersMutex_);
        purgeLocked();
        workers_.push_back(std::move(w));
    }

    void handleClient(std::shared_ptr<IQuicConnection> conn) {
        auto handler = std::make_shared<H3sHandler>(configPtr_, conn);

        // ServeQUICConn equivalent: dispatch bidirectional streams by peeking
        // their leading frame type; datagrams are pumped by the UDP session
        // manager started on successful auth. HTTP/3 request/response handling
        // (including /auth) lives in the transport backend, which drives
        // handler->ServeHTTP directly.
        for (;;) {
            std::shared_ptr<IQuicStream> stream;
            try {
                stream = conn->AcceptStream();
            } catch (...) {
                break; // connection closed
            }
            uint64_t frameType = 0;
            try {
                frameType = VarintRead(*stream);
            } catch (...) {
                continue;
            }
            auto hyStream = std::static_pointer_cast<IHyStream>(stream);
            handler->ProxyStreamHijacker(frameType, hyStream);
        }

        // If the client is authenticated, we need to log the disconnect event
        try {
            if (handler->Authenticated()) {
                if (configPtr_->TrafficLoggerPtr != nullptr) {
                    configPtr_->TrafficLoggerPtr->LogOnlineState(handler->AuthID(), false);
                }
                if (configPtr_->EventLoggerPtr != nullptr) {
                    configPtr_->EventLoggerPtr->Disconnect(conn->RemoteAddr(),
                                                           handler->AuthID(), "");
                }
            }
        } catch (...) {
        }
        conn->CloseWithError(CloseErrCodeOK, "");
    }

    // Shared with every H3sHandler so handler worker threads stay safe even
    // if the ServerImpl itself is destroyed while a connection lives on.
    std::shared_ptr<Config> configPtr_;
    std::unique_ptr<IQuicListener> listener_;
    std::mutex workersMutex_;
    std::vector<Worker> workers_;
    std::atomic<bool> closed_{false};
};

} // namespace

size_t ServerActiveWorkers(Server& s) {
    auto* impl = dynamic_cast<ServerImpl*>(&s);
    return impl ? impl->ActiveWorkers() : 0;
}

void ServerWaitWorkersIdle(Server& s, int timeoutMs) {
    for (int i = 0; i < timeoutMs / 10; i++) {
        if (ServerActiveWorkers(s) == 0) return;
        SleepFor(Duration::FromMillis(10));
    }
}

// ---------------------------------------------------------------------------
// Factories

namespace {
QuicBackendFactory g_backend = nullptr;
std::mutex g_backendMutex;
} // namespace

void SetGlobalQuicBackend(QuicBackendFactory factory) {
    std::lock_guard<std::mutex> lk(g_backendMutex);
    g_backend = std::move(factory);
}

std::unique_ptr<Server> NewServer(Config config) {
    QuicBackendFactory factory;
    {
        std::lock_guard<std::mutex> lk(g_backendMutex);
        factory = g_backend;
    }
    if (!factory) {
        throw Error("no QUIC backend registered; use SetGlobalQuicBackend or "
                    "NewServerWithListener");
    }
    config.Fill();
    auto listener = factory(config);
    return std::make_unique<ServerImpl>(std::move(config), std::move(listener));
}

std::unique_ptr<Server> NewServerWithListener(Config config,
                                              std::unique_ptr<IQuicListener> listener) {
    config.Fill();
    return std::make_unique<ServerImpl>(std::move(config), std::move(listener));
}

} // namespace hy2::server
