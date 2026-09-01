// win_redirector.hpp - Windows redirect implementation using WinDivert.
// Provides equivalent functionality to Linux SO_ORIGINAL_DST.
#pragma once

#ifdef _WIN32

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include "hy2/platform/platform_common.hpp"

namespace hy2::platform::windows_impl {

// WindowsTcpRedirector - TCP redirect using WinDivert.
// Captures TCP packets, extracts original destination from IP/TCP headers.
class WindowsTcpRedirector : public IRedirector {
public:
    WindowsTcpRedirector(TcpDialFunc dialFunc,
                         std::shared_ptr<IRedirectorEventLogger> logger);
    ~WindowsTcpRedirector() override;

    bool Start(const std::string& listenAddr) override;
    void Stop() override;

private:
    void captureLoop();
    void handleConnection(const std::string& clientAddr,
                          const std::string& originalDest);

    TcpDialFunc dialFunc_;
    std::shared_ptr<IRedirectorEventLogger> logger_;
    std::atomic<bool> running_{false};
    std::thread captureThread_;
    void* winDivertHandle_ = nullptr;
};

} // namespace hy2::platform::windows_impl

#endif // _WIN32
