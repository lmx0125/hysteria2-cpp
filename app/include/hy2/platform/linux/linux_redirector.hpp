// linux_redirector.hpp - Linux REDIRECT transparent proxy implementation.
// Uses SO_ORIGINAL_DST getsockopt to recover original destination.
// Requires: iptables -t nat -j REDIRECT rules.
#pragma once

#ifdef __linux__

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include "hy2/platform/platform_common.hpp"

namespace hy2::platform::linux_impl {

// LinuxTcpRedirector - TCP redirect using SO_ORIGINAL_DST.
// When iptables REDIRECT redirects a connection to our listener,
// getsockopt(SO_ORIGINAL_DST) recovers the original destination.
class LinuxTcpRedirector : public IRedirector {
public:
    LinuxTcpRedirector(TcpDialFunc dialFunc,
                       std::shared_ptr<IRedirectorEventLogger> logger);
    ~LinuxTcpRedirector() override;

    bool Start(const std::string& listenAddr) override;
    void Stop() override;

private:
    void acceptLoop(int listenFd);
    void handleConnection(int connFd);
    std::string getOriginalDest(int fd);

    TcpDialFunc dialFunc_;
    std::shared_ptr<IRedirectorEventLogger> logger_;
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    int listenFd_ = -1;
};

} // namespace hy2::platform::linux_impl

#endif // __linux__
