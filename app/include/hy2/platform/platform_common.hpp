// platform_common.hpp - Platform abstraction layer for Hysteria2 CLI.
// Defines interfaces that hide OS-specific implementations.
// Business code must NOT call Win32/Linux APIs directly.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "hy2/io.hpp"

namespace hy2::platform {

// ---------------------------------------------------------------------------
// ITunDevice - TUN device abstraction

class ITunDevice {
public:
    virtual ~ITunDevice() = default;

    // Open the TUN device.
    virtual bool Open() = 0;

    // Read a packet from the TUN device.
    // Returns number of bytes read, 0 on error/close.
    virtual int Read(uint8_t* buf, size_t len) = 0;

    // Write a packet to the TUN device.
    // Returns number of bytes written, 0 on error.
    virtual int Write(const uint8_t* buf, size_t len) = 0;

    // Close the TUN device.
    virtual void Close() = 0;

    // Get the device name.
    virtual std::string Name() const = 0;

    // Get the file descriptor (for platform-specific operations).
    virtual int Fd() const = 0;
};

// ITunDevice configuration
struct TunConfig {
    std::string Name;           // interface name (empty = auto)
    uint32_t MTU = 1500;
    std::string IPv4Addr;       // e.g. "10.0.0.1/24"
    std::string IPv6Addr;       // e.g. "fd00::1/128"
    bool AutoRoute = false;
    bool StrictRoute = false;
};

// Factory: creates a platform-specific TUN device.
std::unique_ptr<ITunDevice> CreateTunDevice(const TunConfig& config);

// ---------------------------------------------------------------------------
// IDestGetter - Get original destination (for transparent proxy)

class IDestGetter {
public:
    virtual ~IDestGetter() = default;

    // Get the original destination address of a connection.
    // For TPROXY: conn.LocalAddr() is the original destination.
    // For redirect: SO_ORIGINAL_DST getsockopt.
    // For WinDivert: parsed from packet metadata.
    // Returns empty string on failure.
    virtual std::string GetOriginalDest(int fd) = 0;
};

// Factory: creates a platform-specific destination getter.
std::unique_ptr<IDestGetter> CreateDestGetter();

// ---------------------------------------------------------------------------
// ITransparentProxy - Transparent proxy (intercept all traffic)

// Event logger interface for transparent proxy events.
class ITransparentProxyEventLogger {
public:
    virtual ~ITransparentProxyEventLogger() = default;

    // Called when a new connection is intercepted.
    // addr: original destination the client wanted to reach.
    // reqAddr: the request address (may differ from addr in some modes).
    virtual void OnConnect(const std::string& addr, const std::string& reqAddr) = 0;

    // Called when a connection closes.
    // addr: original destination.
    // reqAddr: the request address.
    // err: error message (empty on clean close).
    virtual void OnError(const std::string& addr, const std::string& reqAddr,
                         const std::string& err) = 0;
};

// Callback type for opening a proxied TCP connection.
// addr is the original destination ("host:port").
// Returns a bidirectional stream, or nullptr on error.
using TcpDialFunc = std::function<std::shared_ptr<IByteReaderWriter>(const std::string& addr)>;

// Callback type for opening a proxied UDP session.
// Returns a UDP connection handle, or nullptr on error.
class IHyUDPConn {
public:
    virtual ~IHyUDPConn() = default;
    virtual bool Send(const uint8_t* data, size_t len, const std::string& addr) = 0;
    virtual bool Receive(std::vector<uint8_t>& data, std::string& addr) = 0;
    virtual void Close() = 0;
};
using UdpDialFunc = std::function<std::shared_ptr<IHyUDPConn>()>;

class ITransparentProxy {
public:
    virtual ~ITransparentProxy() = default;

    // Start the transparent proxy (blocks).
    // listenAddr: the address to intercept (e.g., "0.0.0.0:12345").
    // For TCP: listens on this address and accepts redirected connections.
    // For UDP: listens on this address and receives redirected packets.
    virtual bool Start(const std::string& listenAddr) = 0;

    // Stop the transparent proxy.
    virtual void Stop() = 0;
};

// TCP transparent proxy factory.
std::unique_ptr<ITransparentProxy> CreateTcpTransparentProxy(
    TcpDialFunc dialFunc,
    std::shared_ptr<ITransparentProxyEventLogger> logger = nullptr);

// UDP transparent proxy factory.
std::unique_ptr<ITransparentProxy> CreateUdpTransparentProxy(
    UdpDialFunc dialFunc,
    std::shared_ptr<ITransparentProxyEventLogger> logger = nullptr,
    uint32_t timeoutMs = 60000);

// ---------------------------------------------------------------------------
// IRedirector - TCP redirect (iptables REDIRECT / WinDivert)

// Event logger interface for redirect events.
class IRedirectorEventLogger {
public:
    virtual ~IRedirectorEventLogger() = default;

    // Called when a redirected connection is accepted.
    // addr: client address.
    // reqAddr: original destination (recovered via SO_ORIGINAL_DST or WinDivert).
    virtual void OnConnect(const std::string& addr, const std::string& reqAddr) = 0;

    // Called when a redirected connection closes.
    // addr: client address.
    // reqAddr: original destination.
    // err: error message (empty on clean close).
    virtual void OnError(const std::string& addr, const std::string& reqAddr,
                         const std::string& err) = 0;
};

class IRedirector {
public:
    virtual ~IRedirector() = default;

    // Start the redirector (blocks).
    // listenAddr: the address to listen on (e.g., "0.0.0.0:12345").
    virtual bool Start(const std::string& listenAddr) = 0;

    // Stop the redirector.
    virtual void Stop() = 0;
};

// TCP redirector factory.
std::unique_ptr<IRedirector> CreateTcpRedirector(
    TcpDialFunc dialFunc,
    std::shared_ptr<IRedirectorEventLogger> logger = nullptr);

// ---------------------------------------------------------------------------
// IFirewallManager - Firewall rule management

struct FirewallPortRange {
    uint16_t start;
    uint16_t end;
};

class IFirewallManager {
public:
    virtual ~IFirewallManager() = default;

    // Setup UDP port redirect rules to redirect traffic to the given port.
    // Returns true on success.
    virtual bool SetupUDPPortRedirect(const std::string& listenAddr,
                                       uint16_t listenPort,
                                       const std::vector<FirewallPortRange>& ports) = 0;

    // Cleanup all rules created by this manager.
    virtual void Cleanup() = 0;
};

// Factory: creates a platform-specific firewall manager.
std::unique_ptr<IFirewallManager> CreateFirewallManager();

// ---------------------------------------------------------------------------
// MimicConfig - Configuration for traffic mimic (disguise UDP as TCP)

struct MimicConfig {
    bool Enabled = false;
    std::string Interface;      // network interface (empty = auto-detect)
    std::string XDPMode;        // "native", "skb", or empty (auto)
    std::string Path;           // path to mimic binary (empty = search PATH)
    std::vector<std::string> ExtraArgs;
};

enum class MimicRole {
    Client,
    Server
};

// IMimicInstance - Running mimic process handle
class IMimicInstance {
public:
    virtual ~IMimicInstance() = default;
    virtual void Close() = 0;
};

// Start mimic. Returns nullptr if disabled.
// onExit is called if mimic exits unexpectedly.
std::shared_ptr<IMimicInstance> StartMimic(
    const MimicConfig& cfg,
    MimicRole role,
    const std::vector<std::string>& addresses,
    std::function<void(const std::string&)> logFunc = nullptr,
    std::function<void(const std::string&)> onExit = nullptr);

// ---------------------------------------------------------------------------
// SocketOptions - Cross-platform socket option application

class SocketOptions {
public:
    // Apply platform-appropriate socket options to a UDP socket.
    // Silently ignores unsupported options (graceful degradation).
    static void ApplyUDPOptions(int fd,
                                 const std::string* bindInterface = nullptr,
                                 const uint32_t* firewallMark = nullptr);
};

} // namespace hy2::platform
