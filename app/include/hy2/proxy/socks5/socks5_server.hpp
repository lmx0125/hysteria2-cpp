// socks5_server.hpp - SOCKS5 proxy server using Hysteria2 client as outbound.
// Rewrite of app/internal/socks5/server.go.
// Cross-platform: no platform-specific code.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "hy2/client.hpp"
#include "hy2/server_iface.hpp"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
#endif

namespace hy2::proxy::socks5 {

// SOCKS5 protocol constants (RFC 1928)
constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kCmdUDP = 0x03;
constexpr uint8_t kMethodNone = 0x00;
constexpr uint8_t kMethodUsernamePassword = 0x02;
constexpr uint8_t kMethodUnsupportAll = 0xFF;
constexpr uint8_t kUserPassStatusSuccess = 0x00;
constexpr uint8_t kUserPassStatusFailure = 0x01;
constexpr uint8_t kRepSuccess = 0x00;
constexpr uint8_t kRepServerFailure = 0x01;
constexpr uint8_t kRepHostUnreachable = 0x04;
constexpr uint8_t kRepCommandNotSupported = 0x07;
constexpr uint8_t kAtypIPv4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypIPv6 = 0x04;
constexpr int kUdpBufferSize = 4096;

// EventLogger for SOCKS5 server events.
class ISocks5EventLogger {
public:
    virtual ~ISocks5EventLogger() = default;
    virtual void TCPRequest(const std::string& addr, const std::string& reqAddr) {}
    virtual void TCPError(const std::string& addr, const std::string& reqAddr,
                          const std::string& err) {}
    virtual void UDPRequest(const std::string& addr) {}
    virtual void UDPError(const std::string& addr, const std::string& err) {}
};

// Socks5Server is a SOCKS5 proxy server using a Hysteria2 client as outbound.
// Matches Go's app/internal/socks5/server.go behavior exactly.
//
// Sessions run on detached threads (an accept loop must never block on a
// handshake) and hold the server alive via shared_from_this. Hosts that
// destroy shared resources which sessions still use (Hysteria client, TUN,
// packet engine) MUST stop the accept loop and then wait for
// WaitForSessions() before tearing them down - a session that is mid-request
// otherwise touches freed memory.
class Socks5Server : public std::enable_shared_from_this<Socks5Server> {
public:
    std::shared_ptr<client::Client> HyClient;
    std::function<bool(const std::string&, const std::string&)> AuthFunc; // nil = no auth
    bool DisableUDP = false;
    ISocks5EventLogger* EventLogger = nullptr;

    // Serve accepts connections on listener and dispatches them.
    // Blocks until stop is set to true.
    void Serve(std::shared_ptr<server::IConn> listener);

    // ServeOnPort binds to port and runs the accept loop.
    // Blocks until stop is set to true. Returns false on bind/listen error.
    bool ServeOnPort(uint16_t port, std::atomic<bool>& stop);

    // Handle a single accepted connection (protocol negotiation + dispatch).
    void dispatch(std::shared_ptr<server::IConn> conn);

    // Live detached sessions. WaitForSessions() returns true when they are all
    // gone, false on timeout (the process should then exit without tearing
    // shared state down under them).
    int ActiveSessions() const { return activeSessions_.load(std::memory_order_relaxed); }
    bool WaitForSessions(std::chrono::milliseconds timeout);

    // Closes the sessions' client sockets: an idle keep-alive session blocked
    // in recv() ends immediately instead of holding shutdown for the whole
    // drain timeout. Call before WaitForSessions().
    void CloseSessions();

private:
    void TrackConn(const std::shared_ptr<server::IConn>& conn);
    std::mutex connMu_;
    std::vector<std::weak_ptr<server::IConn>> conns_;

    void SessionBegin() { activeSessions_.fetch_add(1, std::memory_order_relaxed); }
    void SessionEnd() {
        activeSessions_.fetch_sub(1, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lk(sessionMu_);
        sessionCv_.notify_all();
    }

    std::atomic<int> activeSessions_{0};
    std::mutex sessionMu_;
    std::condition_variable sessionCv_;
    bool negotiate(server::IConn& conn);
    void handleTCP(std::shared_ptr<server::IConn> conn,
                   const std::string& targetAddr);
    void handleUDP(std::shared_ptr<server::IConn> conn,
                   const std::string& targetAddr);
};

// ---------------------------------------------------------------------------
// TcpListener - cross-platform TCP listener that wraps a socket.
// Used by ServeOnPort() and proxy_gateway.
class TcpListener {
public:
#ifdef _WIN32
    using socket_t = SOCKET;
    static constexpr socket_t kInvalid = INVALID_SOCKET;
#else
    using socket_t = int;
    static constexpr socket_t kInvalid = -1;
#endif

    TcpListener() = default;
    ~TcpListener();

    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;

    // Bind and listen on the given port. Returns false on error.
    bool Listen(uint16_t port);

    // Accept the next connection. Blocks until a connection arrives.
    // Returns nullptr if the listener is closed.
    std::shared_ptr<server::IConn> Accept();

    // Close the listener socket, unblocking any pending Accept().
    void Close();

private:
    socket_t fd_ = kInvalid;
};

// Parse SOCKS5 address from ATYP + addr + port bytes.
// Returns "host:port" string.
std::string parseSocks5Address(uint8_t atyp, const uint8_t* addr, size_t addrLen,
                                const uint8_t* port);

// Build SOCKS5 address bytes from "host:port" string.
// Returns ATYP + addr bytes + port bytes.
std::vector<uint8_t> buildSocks5Address(const std::string& hostPort);

} // namespace hy2::proxy::socks5
