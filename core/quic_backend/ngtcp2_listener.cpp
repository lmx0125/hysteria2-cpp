#include "hy2/quic_backend/ngtcp2_listener.hpp"

#include <cstring>
#include <iostream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <mmsystem.h>
  #pragma comment(lib, "winmm.lib")
#else
  #include <fcntl.h>
  #include <sys/select.h>
  #include <unistd.h>
#endif

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "hy2/quic_backend/ngtcp2_connection.hpp"
#include "hy2/quic_backend/udp_socket.hpp"
#include "hy2/quic_backend/io_poll.hpp"

#include "hy2/debug_print.hpp"

#include <cstdio>
#include <cstdlib>

namespace hy2::quic_backend {

static bool QuicDebugEnabled() {
    static bool v = std::getenv("HY2_QUIC_DEBUG") != nullptr;
    return v;
}

// ALPN selection for incoming connections: prefer HTTP/3 ("h3").
// quic-go (official Hysteria2) aborts the handshake unless the server
// selects one of its offered protocols.
static int AlpnSelectCb(SSL* /*ssl*/, const unsigned char** out,
                        unsigned char* outlen, const unsigned char* in,
                        unsigned int inlen, void* /*arg*/) {
    static const unsigned char h3[] = {2, 'h', '3'};
    if (SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                              h3, sizeof(h3), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

// ---------------------------------------------------------------------------
// Wake pipe: lets application threads (Stream::Write) wake the RecvLoop
// so it flushes pending write data immediately instead of waiting for
// select() timeout.
// ---------------------------------------------------------------------------
void Ngtcp2Listener::InitWakePipe() {
#ifdef _WIN32
    // Windows: use a loopback UDP socket pair (select()-compatible)
    wakeRead_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    wakeWrite_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (wakeRead_ == INVALID_SOCKET || wakeWrite_ == INVALID_SOCKET) return;

    // Non-blocking is REQUIRED: RecvLoop drains the pipe with a
    // while(recv(...)>0) loop, and a blocking read-end would stall
    // forever on the final (empty) recv, deadlocking the listener
    // (no more packets read, no ACKs sent, no Drive()).
    u_long nonBlocking = 1;
    ioctlsocket(wakeRead_, FIONBIO, &nonBlocking);
    ioctlsocket(wakeWrite_, FIONBIO, &nonBlocking);

    // Bind read end to 127.0.0.1:0
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    int len = sizeof(addr);
    bind(wakeRead_, (struct sockaddr*)&addr, len);
    getsockname(wakeRead_, (struct sockaddr*)&addr, &len);

    // Connect write end to read end
    connect(wakeWrite_, (struct sockaddr*)&addr, len);
#else
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        wakeRead_ = -1;
        wakeWrite_ = -1;
        return;
    }
    wakeRead_ = pipefd[0];
    wakeWrite_ = pipefd[1];
    // Set non-blocking so Write doesn't stall if pipe is full
    fcntl(wakeRead_, F_SETFL, O_NONBLOCK);
    fcntl(wakeWrite_, F_SETFL, O_NONBLOCK);
#endif
}

void Ngtcp2Listener::CloseWakePipe() {
#ifdef _WIN32
    if (wakeRead_ != INVALID_SOCKET) { closesocket(wakeRead_); wakeRead_ = INVALID_SOCKET; }
    if (wakeWrite_ != INVALID_SOCKET) { closesocket(wakeWrite_); wakeWrite_ = INVALID_SOCKET; }
#else
    if (wakeRead_ >= 0) { close(wakeRead_); wakeRead_ = -1; }
    if (wakeWrite_ >= 0) { close(wakeWrite_); wakeWrite_ = -1; }
#endif
}

std::shared_ptr<Ngtcp2Listener> Ngtcp2Listener::Create(const ServerParams& params) {
    auto self = std::shared_ptr<Ngtcp2Listener>(new Ngtcp2Listener());
    if (!self->Init(params)) return nullptr;
    self->running_ = true;
    self->recvThread_ = std::thread(&Ngtcp2Listener::RecvLoop, self.get());
    return self;
}

bool Ngtcp2Listener::Init(const ServerParams& params) {
    params_ = params;

#ifdef _WIN32
    // Bind may be the first socket call in the process (interop harness).
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] WSAStartup failed\n");
        return false;
    }
    // 1ms timer resolution: without it, WSAPoll() timeouts round up to the
    // system clock granularity (~15.6ms), delaying QUIC timers (PTO/ACK).
    timeBeginPeriod(1);
#endif

    static std::once_flag cryptoInitFlag;
    bool initOk = true;
    std::call_once(cryptoInitFlag, [&]() {
        if (ngtcp2_crypto_ossl_init() != 0) {
            if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] ossl_init failed\n");
            initOk = false;
        }
    });
    if (!initOk) return false;

    // Create SSL context
    sslCtx_ = SSL_CTX_new(TLS_server_method());
    if (!sslCtx_) {
        if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] SSL_CTX_new failed: %lu\n", (unsigned long)ERR_get_error());
        return false;
    }
    SSL_CTX_set_min_proto_version(sslCtx_, TLS1_3_VERSION);
    SSL_CTX_set_alpn_select_cb(sslCtx_, AlpnSelectCb, nullptr);

    // Load certificates (chain: first is leaf, rest are intermediates)
    for (size_t i = 0; i < params.certChainPEM.size(); ++i) {
        BIO* bio = BIO_new_mem_buf(params.certChainPEM[i].data(),
                                   static_cast<int>(params.certChainPEM[i].size()));
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!cert) {
            if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] parse cert %zu failed: %lu\n", i, (unsigned long)ERR_get_error());
            SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false;
        }
        if (SSL_CTX_use_certificate(sslCtx_, cert) != 1) {
            if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] use_certificate failed: %lu\n", (unsigned long)ERR_get_error());
            X509_free(cert);
            SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false;
        }
        X509_free(cert);
    }

    // Load private key
    if (!params.privateKeyPEM.empty()) {
        BIO* bio = BIO_new_mem_buf(params.privateKeyPEM[0].data(),
                                   static_cast<int>(params.privateKeyPEM[0].size()));
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] parse key failed: %lu\n", (unsigned long)ERR_get_error());
            SSL_CTX_free(sslCtx_); sslCtx_ = nullptr; return false;
        }
        SSL_CTX_use_PrivateKey(sslCtx_, pkey);
        EVP_PKEY_free(pkey);
        if (SSL_CTX_check_private_key(sslCtx_) != 1) {
            if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] check_private_key failed: %lu\n", (unsigned long)ERR_get_error());
            SSL_CTX_free(sslCtx_);
            sslCtx_ = nullptr;
            return false;
        }
    }

    // Create and bind UDP socket
    socket_ = std::make_unique<UdpSocket>();
    if (!socket_->Bind(params.bindAddr, params.port)) {
        if (QuicDebugEnabled()) std::fprintf(stderr, "[quic] bind %s:%u failed: %d\n",
                                             params.bindAddr.c_str(), params.port,
#ifdef _WIN32
                                             WSAGetLastError()
#else
                                             errno
#endif
        );
        SSL_CTX_free(sslCtx_);
        sslCtx_ = nullptr;
        return false;
    }

    InitWakePipe();
    return true;
}

void Ngtcp2Listener::RegisterConn(uint64_t key,
                                   std::shared_ptr<Ngtcp2Connection> conn) {
    // Give the connection a pointer to the wake pipe so Stream::Write()
    // can wake the RecvLoop thread immediately.
#ifdef _WIN32
    if (wakeWrite_ != INVALID_SOCKET) conn->SetWakeFd(&wakeWrite_);
#else
    if (wakeWrite_ >= 0) conn->SetWakeFd(&wakeWrite_);
#endif
    std::lock_guard<std::mutex> lk(connsMu_);
    conns_[key] = std::move(conn);
}

void Ngtcp2Listener::NotifyHandshakeComplete(std::shared_ptr<IQuicConnection> conn) {
    {
        std::lock_guard<std::mutex> lk(pendingMu_);
        pendingConns_.push_back(std::move(conn));
    }
    pendingCv_.notify_all();
}

static uint64_t AddrKey(const struct sockaddr* addr, socklen_t len) {
    uint8_t buf[sizeof(sockaddr_storage) + sizeof(len)] = {};
    memcpy(buf, addr, len);
    memcpy(buf + len, &len, sizeof(len));
    // FNV-1a
    uint64_t h = 1469598103934665603ull;
    for (uint8_t b : buf) {
        h ^= b;
        h *= 1099511628211ull;
    }
    return h;
}

void Ngtcp2Listener::HandlePacket(const uint8_t* data, size_t len,
                                  const struct sockaddr* from, socklen_t fromlen,
                                  const struct sockaddr* local, socklen_t locallen) {
    uint64_t key = AddrKey(from, fromlen);

    std::shared_ptr<Ngtcp2Connection> existing;
    {
        std::lock_guard<std::mutex> lk(connsMu_);
        auto it = conns_.find(key);
        if (it != conns_.end()) existing = it->second;
    }

    // Long-header (Initial) detection BEFORE routing: lazy clients (like
    // hysteria2) tear down their QUIC connection after auth and reconnect
    // later, often re-using the same UDP 4-tuple. If a fresh Initial
    // carries a different source CID than the connection we have on file,
    // it is a NEW connection that must replace the stale one.
    bool isInitial = len > 0 && (data[0] & 0x80) != 0;
    ngtcp2_pkt_hd hd;
    bool parsedInitial =
        isInitial && ngtcp2_accept(&hd, data, len) == 0;

    if (existing && parsedInitial) {
        const ngtcp2_cid* oldClientScid = &existing->ClientScid();
        bool sameConn = oldClientScid->datalen == hd.scid.datalen &&
                        memcmp(oldClientScid->data, hd.scid.data,
                               hd.scid.datalen) == 0;
        if (!sameConn) {
            if (QuicDebugEnabled()) {
                std::fprintf(stderr,
                             "[quic] new Initial on same 4-tuple - replacing "
                             "stale connection\n");
            }
            std::lock_guard<std::mutex> lk(connsMu_);
            conns_.erase(key);
            existing.reset();
        }
    }

    if (!existing) {
        if (!parsedInitial) {
            if (QuicDebugEnabled()) {
                std::fprintf(stderr, "[quic] drop non-initial from unknown (%zu B)\n", len);
            }
            return;
        }
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[quic] NEW INCOMING CONNECTION %zu B\n", len);
        }

        Ngtcp2Connection::ServerInitParams p;
        p.listener = this;
        p.sslCtx = sslCtx_;
        p.hd = &hd;
        p.remoteAddr = from;
        p.remoteAddrLen = fromlen;
        p.localAddr = local;
        p.localAddrLen = locallen;
        p.quicCfg = params_.quicCfg;
        p.datagramEnabled = params_.datagramEnabled;

        auto conn = Ngtcp2Connection::CreateServer(p);
        if (!conn) return;
        RegisterConn(key, conn);

        existing = conn;
    }

    existing->OnUdpRecv(data, len, from, fromlen);
}

void Ngtcp2Listener::RecvLoop() {
    uint8_t buf[65536];
    struct sockaddr_storage from{}, local{};
    socklen_t fromlen{};

    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[quic] recvloop enter fd=%d\n",
                     socket_ ? socket_->GetFd() : -1);
    }

    // The bound local address never changes for the listener's lifetime -
    // query it once instead of calling getsockname() on every loop
    // iteration (one syscall per event at full load).
    socklen_t locallen = sizeof(local);
    if (socket_ && getsockname(socket_->GetFd(),
                               reinterpret_cast<struct sockaddr*>(&local),
                               &locallen) != 0) {
        memset(&local, 0, sizeof(local));
        locallen = sizeof(struct sockaddr_in);
        local.ss_family = AF_INET;
    }

    while (running_) {
        if (std::getenv("HY2_BW_DIAG")) {
            static auto diagT = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (now - diagT >= std::chrono::seconds(1)) {
                std::fprintf(stderr, "[RECVLOOP] event-driven\n");
                diagT = now;
            }
        }

        // Event-driven wait: block until the socket has data, a stream write
        // wakes us, or the nearest QUIC timer across all connections fires.
        // There is NO fixed-cadence sleep: packets leave the moment the
        // application submits them, so RTT samples measure the network
        // instead of our scheduler.
#ifdef _WIN32
        int wakeFd = (wakeRead_ != INVALID_SOCKET)
                         ? static_cast<int>(wakeRead_) : -1;
#else
        int wakeFd = wakeRead_;
#endif
        IoWaitResult res = IoWait(GetFd(), wakeFd, GetNearestExpiry());
        if (res == IoWaitResult::kError) break;
        if (!running_) break;

        // Drain wake pipe signal (application thread wrote data to a stream)
#ifdef _WIN32
        if (wakeRead_ != INVALID_SOCKET) {
            char tmp[8]; while (recv(wakeRead_, tmp, sizeof(tmp), 0) > 0);
        }
#else
        if (wakeRead_ >= 0) {
            char tmp[8];
            while (read(wakeRead_, tmp, sizeof(tmp)) > 0) {}
        }
#endif

        // Drain all available packets (non-blocking tight loop). Each
        // OnUdpRecv marks its connection tx-pending (ACKs are owed).
        for (;;) {
            fromlen = sizeof(from);
            int n = socket_->RecvFrom(buf, sizeof(buf),
                                      reinterpret_cast<struct sockaddr*>(&from),
                                      &fromlen);
            if (n <= 0) break;
            HandlePacket(buf, static_cast<size_t>(n),
                         reinterpret_cast<struct sockaddr*>(&from), fromlen,
                         reinterpret_cast<struct sockaddr*>(&local), locallen);
        }

        // Timers + flushes. Only connections that owe packets (incoming
        // data, stream writes, or an overdue timer) are driven - this
        // keeps the cost per event O(active) instead of O(all conns).
        std::vector<std::shared_ptr<Ngtcp2Connection>> snapshot;
        {
            std::lock_guard<std::mutex> lk(connsMu_);
            snapshot.reserve(conns_.size());
            for (auto& kv : conns_) snapshot.push_back(kv.second);
        }
        for (auto& c : snapshot) {
            if (c->TimerOverdue()) {
                c->OnTimeout();
            }
            if (c->ConsumeTxPending()) {
                c->Drive();
            }
        }

        // Drop closed connections periodically.
        {
            std::lock_guard<std::mutex> lk(connsMu_);
            for (auto it = conns_.begin(); it != conns_.end();) {
                if (it->second.use_count() <= 1 && it->second->IsHandshakeComplete()) {
                    DBG_LOG("[RecvLoop] DROPPING connection", "use_count", it->second.use_count(), "key", it->first);
                    it = conns_.erase(it);
                } else {
                    ++it;
                }
            }
            DBG_LOG("[RecvLoop] conns_ size after cleanup", conns_.size());
        }
    }
}

Ngtcp2Listener::~Ngtcp2Listener() {
    Close();
    CloseWakePipe();
    if (sslCtx_) {
        SSL_CTX_free(sslCtx_);
        sslCtx_ = nullptr;
    }
}

std::shared_ptr<IQuicConnection> Ngtcp2Listener::Accept() {
    std::unique_lock<std::mutex> lk(pendingMu_);
    pendingCv_.wait(lk, [this] {
        return !pendingConns_.empty() || closed_.load();
    });
    if (pendingConns_.empty()) return nullptr;
    auto conn = std::move(pendingConns_.front());
    pendingConns_.erase(pendingConns_.begin());
    return conn;
}

void Ngtcp2Listener::Close() {
    if (!closed_.exchange(true)) {
        running_ = false;
        // Unblock the RecvLoop's poll()/WSAPoll() so it can observe
        // running_ == false immediately (it may be blocked with no
        // deadline while no connections exist).
#ifdef _WIN32
        if (wakeWrite_ != INVALID_SOCKET) {
            uint64_t v = 1;
            send(wakeWrite_, reinterpret_cast<const char*>(&v), sizeof(v), 0);
        }
#else
        if (wakeWrite_ >= 0) {
            uint64_t v = 1;
            [[maybe_unused]] ssize_t n = write(wakeWrite_, &v, sizeof(v));
        }
#endif
        if (recvThread_.joinable()) {
            recvThread_.join();
        }
    }
    {
        std::lock_guard<std::mutex> lk(pendingMu_);
        pendingConns_.clear();
    }
    pendingCv_.notify_all();
    if (socket_) socket_->Close();
}

int Ngtcp2Listener::GetFd() const {
    return socket_ ? socket_->GetFd() : -1;
}

std::chrono::steady_clock::time_point Ngtcp2Listener::GetNearestExpiry() {
    auto nearest = std::chrono::steady_clock::time_point::max();
    std::lock_guard<std::mutex> lk(connsMu_);
    for (auto& kv : conns_) {
        auto exp = kv.second->GetExpiry();
        if (exp < nearest) nearest = exp;
    }
    return nearest;
}

} // namespace hy2::quic_backend



