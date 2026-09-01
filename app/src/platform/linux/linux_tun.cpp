// linux_tun.cpp - Linux TUN device implementation.
// Uses /dev/net/tun with ioctl(TUNSETIFF).

#ifdef __linux__

#include "hy2/platform/linux/linux_tun.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cstring>

namespace hy2::platform::linux_impl {

LinuxTunDevice::LinuxTunDevice(const TunConfig& config)
    : config_(config) {}

LinuxTunDevice::~LinuxTunDevice() {
    Close();
}

bool LinuxTunDevice::Open() {
    fd_ = open("/dev/net/tun", O_RDWR);
    if (fd_ < 0) return false;

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN device, no packet info

    if (!config_.Name.empty()) {
        strncpy(ifr.ifr_name, config_.Name.c_str(), IFNAMSIZ - 1);
    }

    if (ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        close(fd_);
        fd_ = -1;
        return false;
    }

    name_ = ifr.ifr_name;

    // Set MTU
    int mtu = config_.MTU;
    auto sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct ifreq ifrMtu{};
        strncpy(ifrMtu.ifr_name, name_.c_str(), IFNAMSIZ - 1);
        ifrMtu.ifr_mtu = mtu;
        ioctl(sock, SIOCSIFMTU, &ifrMtu);
        close(sock);
    }

    // Configure IP addresses if provided
    if (!config_.IPv4Addr.empty()) {
        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            // Parse CIDR (e.g., "10.0.0.1/24")
            auto slash = config_.IPv4Addr.find('/');
            std::string ip = config_.IPv4Addr.substr(0, slash);

            struct ifreq ifrAddr{};
            strncpy(ifrAddr.ifr_name, name_.c_str(), IFNAMSIZ - 1);

            auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifrAddr.ifr_addr);
            sin->sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &sin->sin_addr);
            ioctl(sock, SIOCSIFADDR, &ifrAddr);

            // Set netmask
            if (slash != std::string::npos) {
                int prefixLen = std::atoi(config_.IPv4Addr.c_str() + slash + 1);
                uint32_t mask = 0;
                for (int i = 0; i < prefixLen; ++i) {
                    mask = (mask << 1) | 1;
                }
                mask = htonl(mask);

                struct ifreq ifrMask{};
                strncpy(ifrMask.ifr_name, name_.c_str(), IFNAMSIZ - 1);
                auto* sinMask = reinterpret_cast<struct sockaddr_in*>(&ifrMask.ifr_addr);
                sinMask->sin_family = AF_INET;
                memcpy(&sinMask->sin_addr, &mask, 4);
                ioctl(sock, SIOCSIFNETMASK, &ifrMask);
            }

            // Bring interface up
            struct ifreq ifrUp{};
            strncpy(ifrUp.ifr_name, name_.c_str(), IFNAMSIZ - 1);
            ioctl(sock, SIOCGIFFLAGS, &ifrUp);
            ifrUp.ifr_flags |= IFF_UP | IFF_RUNNING;
            ioctl(sock, SIOCSIFFLAGS, &ifrUp);

            close(sock);
        }
    }

    // Configure IPv6 if provided
    if (!config_.IPv6Addr.empty()) {
        // IPv6 configuration requires netlink on modern Linux
        // For simplicity, we'll use a basic approach
        // In production, use libnl or similar
    }

    // Set up routing if AutoRoute is enabled
    if (config_.AutoRoute) {
        // Route setup requires netlink or system commands
        // This would be implemented with ip route commands
    }

    return true;
}

int LinuxTunDevice::Read(uint8_t* buf, size_t len) {
    if (fd_ < 0) return 0;
    return read(fd_, buf, len);
}

int LinuxTunDevice::Write(const uint8_t* buf, size_t len) {
    if (fd_ < 0) return 0;
    return write(fd_, buf, len);
}

void LinuxTunDevice::Close() {
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

std::string LinuxTunDevice::Name() const {
    return name_;
}

int LinuxTunDevice::Fd() const {
    return fd_;
}

} // namespace hy2::platform::linux_impl

#endif // __linux__
