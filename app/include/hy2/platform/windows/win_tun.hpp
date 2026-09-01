// win_tun.hpp - Windows TUN device implementation using Wintun.
// Wintun is a minimalistic TUN driver for Windows.
// https://www.wintun.net/
#pragma once

#ifdef _WIN32

#include "hy2/platform/platform_common.hpp"

#include <string>

namespace hy2::platform::windows_impl {

// WindowsTunDevice - TUN device using Wintun driver.
class WindowsTunDevice : public ITunDevice {
public:
    explicit WindowsTunDevice(const TunConfig& config);
    ~WindowsTunDevice() override;

    bool Open() override;
    int Read(uint8_t* buf, size_t len) override;
    int Write(const uint8_t* buf, size_t len) override;
    void Close() override;
    std::string Name() const override;
    int Fd() const override;

private:
    TunConfig config_;
    void* tunHandle_ = nullptr;  // WINTUN_ADAPTER_HANDLE
    std::string name_;
    int fd_ = -1;  // For compatibility; Wintun uses its own handle
};

} // namespace hy2::platform::windows_impl

#endif // _WIN32
