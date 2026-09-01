#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
#endif

#include <openssl/ssl.h>

#include "hy2/quic.hpp"
#include "hy2/quic_config.hpp"
#include "hy2/quic_backend/udp_socket.hpp"

namespace hy2::quic_backend {

class Ngtcp2Connection;

// ---------------------------------------------------------------------------
// Ngtcp2Listener: listens on a UDP socket, performs server-side QUIC
// handshake, and yields fully-established Ngtcp2Connection objects.
// Implements IQuicListener.
// ---------------------------------------------------------------------------
class Ngtcp2Listener : public IQuicListener {
public:
    struct ServerParams {
        std::string bindAddr;          // "0.0.0.0" or "::"
        uint16_t port = 443;
        // TLS certificates
        std::vector<std::string> certChainPEM;
        std::vector<std::string> privateKeyPEM;
        std::vector<std::string> clientCAPEM;
        // QUIC settings
        QuicConfig quicCfg;
        bool datagramEnabled = false;
    };

    // Factory method: creates, binds, and starts the listener.
    // Returns nullptr on error.
    static std::shared_ptr<Ngtcp2Listener> Create(const ServerParams& params);

    ~Ngtcp2Listener() override;

    // Blocks until a new connection arrives or Close() is called.
    // Returns nullptr when the listener is shutting down.
    std::shared_ptr<IQuicConnection> Accept() override;
    void Close() override;

    // Access the raw UDP fd for external event loops (epoll/IOCP).
    int GetFd() const;
    // Raw socket pointer for server-side connection sends (non-owning).
    UdpSocket* GetSocketRaw() { return socket_.get(); }

    // Compute the nearest QUIC timer expiry across all active connections.
    // Returns time_point::max() if no connections exist.
    std::chrono::steady_clock::time_point GetNearestExpiry();

    // Internal: route an inbound datagram to an existing connection or
    // start a new server handshake. Called by the receive thread.
    void HandlePacket(const uint8_t* data, size_t len,
                      const struct sockaddr* from, socklen_t fromlen,
                      const struct sockaddr* local, socklen_t locallen);

private:
    Ngtcp2Listener() = default;
    bool Init(const ServerParams& params);
    void RecvLoop();

public:
    // Server-side connection bookkeeping (accessed by Ngtcp2Connection).
    void RegisterConn(uint64_t key, std::shared_ptr<Ngtcp2Connection> conn);
    void NotifyHandshakeComplete(std::shared_ptr<IQuicConnection> conn);

private:
    std::unique_ptr<UdpSocket> socket_;
    SSL_CTX* sslCtx_ = nullptr;
    ServerParams params_;

    std::thread recvThread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> closed_{false};

    // Active connections keyed by remote endpoint hash
    std::mutex connsMu_;
    std::unordered_map<uint64_t, std::shared_ptr<Ngtcp2Connection>> conns_;

    // Pending connections (handshake complete, awaiting Accept())
    std::mutex pendingMu_;
    std::vector<std::shared_ptr<IQuicConnection>> pendingConns_;
    std::condition_variable pendingCv_;

    // Wake pipe: used by Ngtcp2Stream::Write() to wake the RecvLoop
    // when application threads have pending data to send.
#ifdef _WIN32
    SOCKET wakeRead_ = INVALID_SOCKET;  // read end (listener monitors this)
    SOCKET wakeWrite_ = INVALID_SOCKET; // write end (streams signal here)
#else
    int wakeRead_ = -1;   // read end (listener monitors this)
    int wakeWrite_ = -1;  // write end (streams signal here)
#endif
    void InitWakePipe();
    void CloseWakePipe();
};

} // namespace hy2::quic_backend
