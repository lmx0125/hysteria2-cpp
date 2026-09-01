// linux_tun.hpp - Linux TUN device implementation.
// Uses /dev/net/tun with ioctl(TUNSETIFF).
#pragma once

#ifdef __linux__

#include "hy2/platform/platform_common.hpp"

#include <string>

namespace hy2::platform::linux_impl {

// LinuxTunDevice - TUN device using /dev/net/tun.
class LinuxTunDevice : public ITunDevice {
public:
    explicit LinuxTunDevice(const TunConfig& config);
    ~LinuxTunDevice() override;

    bool Open() override;
    int Read(uint8_t* buf, size_t len) override;
    int Write(const uint8_t* buf, size_t len) override;
    void Close() override;
    std::string Name() const override;
    int Fd() const override;

private:
    TunConfig config_;
    int fd_ = -1;
    std::string name_;
};

} // namespace hy2::platform::linux_impl

#endif // __linux__
