// forwarding.hpp - TCP/UDP forwarding using Hysteria2 client as outbound.
// Rewrite of app/internal/forwarding/tcp.go + udp.go.
// Cross-platform: no platform-specific code.
#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "hy2/client.hpp"
#include "hy2/server_iface.hpp"

namespace hy2::proxy::forwarding {

// ---------------------------------------------------------------------------
// TCP Forwarding

class ITcpEventLogger {
public:
    virtual ~ITcpEventLogger() = default;
    virtual void Connect(const std::string& addr) {}
    virtual void Error(const std::string& addr, const std::string& err) {}
};

// TcpTunnel forwards local TCP connections to a fixed remote address via Hysteria2.
// Matches Go's app/internal/forwarding/tcp.go.
class TcpTunnel {
public:
    std::shared_ptr<client::Client> HyClient;
    std::string Remote; // target address (host:port)
    ITcpEventLogger* EventLogger = nullptr;

    // Handle a single accepted connection.
    void handle(std::shared_ptr<server::IConn> conn);
};

// ---------------------------------------------------------------------------
// UDP Forwarding

class IUdpEventLogger {
public:
    virtual ~IUdpEventLogger() = default;
    virtual void Connect(const std::string& addr) {}
    virtual void Error(const std::string& addr, const std::string& err) {}
};

// UdpSessionEntry tracks a single UDP session (client address → Hysteria2 UDP conn).
struct UdpSessionEntry {
    std::shared_ptr<client::HyUDPConn> HyConn;
    std::atomic<int64_t> LastActiveNs{0}; // monotonic timestamp
    std::atomic<bool> Timeout{false};

    void Feed(const uint8_t* data, size_t len, const std::string& remote);
    void ReceiveLoop(std::shared_ptr<server::IUdpConn> localConn,
                     const std::string& clientAddr);
};

// UdpTunnel forwards UDP packets between a local socket and a remote address via Hysteria2.
// Matches Go's app/internal/forwarding/udp.go.
class UdpTunnel {
public:
    std::shared_ptr<client::Client> HyClient;
    std::string Remote;
    int64_t TimeoutNs = 60000000000LL; // 60s default
    IUdpEventLogger* EventLogger = nullptr;

    // Serve reads from localConn and forwards via Hysteria2.
    void Serve(std::shared_ptr<server::IUdpConn> localConn);

private:
    void feed(std::shared_ptr<server::IUdpConn> localConn,
              const std::string& clientAddr,
              const uint8_t* data, size_t len);
    void idleCleanupLoop(std::shared_ptr<server::IUdpConn> localConn,
                         std::atomic<bool>& stop);

    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<UdpSessionEntry>> sessions_;
};

} // namespace hy2::proxy::forwarding
