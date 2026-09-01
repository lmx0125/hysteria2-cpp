// socks5_server.hpp - SOCKS5 proxy server using Hysteria2 client as outbound.
// Rewrite of app/internal/socks5/server.go.
// Cross-platform: no platform-specific code.
#pragma once

#include <functional>
#include <memory>
#include <string>

#include "hy2/client.hpp"
#include "hy2/server_iface.hpp"

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
class Socks5Server {
public:
    std::shared_ptr<client::Client> HyClient;
    std::function<bool(const std::string&, const std::string&)> AuthFunc; // nil = no auth
    bool DisableUDP = false;
    ISocks5EventLogger* EventLogger = nullptr;

    // Serve accepts connections on listener and dispatches them.
    void Serve(std::shared_ptr<server::IConn> listener);

private:
    void dispatch(std::shared_ptr<server::IConn> conn);
    bool negotiate(server::IConn& conn);
    void handleTCP(std::shared_ptr<server::IConn> conn,
                   const std::string& targetAddr);
    void handleUDP(std::shared_ptr<server::IConn> conn,
                   const std::string& targetAddr);
};

// Parse SOCKS5 address from ATYP + addr + port bytes.
// Returns "host:port" string.
std::string parseSocks5Address(uint8_t atyp, const uint8_t* addr, size_t addrLen,
                                const uint8_t* port);

// Build SOCKS5 address bytes from "host:port" string.
// Returns ATYP + addr bytes + port bytes.
std::vector<uint8_t> buildSocks5Address(const std::string& hostPort);

} // namespace hy2::proxy::socks5
