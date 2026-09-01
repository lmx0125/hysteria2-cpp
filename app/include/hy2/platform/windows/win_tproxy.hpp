// win_tproxy.hpp - Windows transparent proxy implementation using WinDivert.
// Intercepts packets at the Windows network stack level.
// Provides equivalent functionality to Linux IP_TRANSPARENT.
#pragma once

#ifdef _WIN32

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "hy2/platform/platform_common.hpp"

namespace hy2::platform::windows_impl {

// WindowsTcpTransparentProxy - TCP transparent proxy using WinDivert.
// Captures TCP SYN packets, extracts original destination, and tunnels
// through Hysteria2 client.
class WindowsTcpTransparentProxy : public ITransparentProxy {
public:
    WindowsTcpTransparentProxy(TcpDialFunc dialFunc,
                                std::shared_ptr<ITransparentProxyEventLogger> logger);
    ~WindowsTcpTransparentProxy() override;

    bool Start(const std::string& listenAddr) override;
    void Stop() override;

private:
    void captureLoop();
    void handleConnection(const std::string& originalDest, uint32_t localAddr,
                          uint16_t localPort, uint32_t remoteAddr, uint16_t remotePort);

    TcpDialFunc dialFunc_;
    std::shared_ptr<ITransparentProxyEventLogger> logger_;
    std::atomic<bool> running_{false};
    std::thread captureThread_;
    void* winDivertHandle_ = nullptr;  // HANDLE
};

// WindowsUdpTransparentProxy - UDP transparent proxy using WinDivert.
// Captures UDP packets, extracts original destination, and tunnels
// through Hysteria2 client.
class WindowsUdpTransparentProxy : public ITransparentProxy {
public:
    WindowsUdpTransparentProxy(UdpDialFunc dialFunc,
                                std::shared_ptr<ITransparentProxyEventLogger> logger,
                                uint32_t timeoutMs);
    ~WindowsUdpTransparentProxy() override;

    bool Start(const std::string& listenAddr) override;
    void Stop() override;

private:
    void captureLoop();

    UdpDialFunc dialFunc_;
    std::shared_ptr<ITransparentProxyEventLogger> logger_;
    uint32_t timeoutMs_;
    std::atomic<bool> running_{false};
    std::thread captureThread_;
    void* winDivertHandle_ = nullptr;  // HANDLE
};

} // namespace hy2::platform::windows_impl

#endif // _WIN32
