// linux_tproxy.hpp - Linux TPROXY transparent proxy implementation.
// Uses IP_TRANSPARENT socket option to intercept redirected traffic.
// Requires: iptables -t mangle -j TPROXY rules.
#pragma once

#ifdef __linux__

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "hy2/platform/platform_common.hpp"

namespace hy2::platform::linux_impl {

// LinuxTcpTProxy - TCP transparent proxy using IP_TRANSPARENT.
// When iptables TPROXY redirects a connection to our listener,
// conn.LocalAddr() returns the original destination.
class LinuxTcpTProxy : public ITransparentProxy {
public:
    LinuxTcpTProxy(TcpDialFunc dialFunc,
                   std::shared_ptr<ITransparentProxyEventLogger> logger);
    ~LinuxTcpTProxy() override;

    bool Start(const std::string& listenAddr) override;
    void Stop() override;

private:
    void acceptLoop(int listenFd);
    void handleConnection(int connFd, const std::string& originalDest);

    TcpDialFunc dialFunc_;
    std::shared_ptr<ITransparentProxyEventLogger> logger_;
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    int listenFd_ = -1;
};

// LinuxUdpTProxy - UDP transparent proxy using IP_TRANSPARENT.
// Reads first packet per (src,dst) pair from listener, then creates
// a connected socket that spoofs the source address.
class LinuxUdpTProxy : public ITransparentProxy {
public:
    LinuxUdpTProxy(UdpDialFunc dialFunc,
                   std::shared_ptr<ITransparentProxyEventLogger> logger,
                   uint32_t timeoutMs);
    ~LinuxUdpTProxy() override;

    bool Start(const std::string& listenAddr) override;
    void Stop() override;

private:
    void receiveLoop(int listenFd);
    void handleSession(int listenFd,
                       const std::string& srcAddr,
                       const std::string& dstAddr,
                       const std::vector<uint8_t>& firstPacket);

    UdpDialFunc dialFunc_;
    std::shared_ptr<ITransparentProxyEventLogger> logger_;
    uint32_t timeoutMs_;
    std::atomic<bool> running_{false};
    std::thread receiveThread_;
    int listenFd_ = -1;
};

} // namespace hy2::platform::linux_impl

#endif // __linux__
