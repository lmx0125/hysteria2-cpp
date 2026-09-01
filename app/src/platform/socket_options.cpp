// socket_options.cpp - Cross-platform socket option application.

#include "hy2/platform/platform_common.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

namespace hy2::platform {

void SocketOptions::ApplyUDPOptions(int fd,
                                     const std::string* bindInterface,
                                     const uint32_t* firewallMark) {
    if (fd < 0) return;

#ifdef _WIN32
    // Windows socket options
    if (bindInterface) {
        // Bind to specific interface
        // SO_BINDTODEVICE is not available on Windows
        // Use IP_PKTINFO or bind to interface IP instead
    }
    if (firewallMark) {
        // Set firewall mark (Windows uses SO_MARK or equivalent)
        // setsockopt(fd, SOL_SOCKET, SO_MARK, firewallMark, sizeof(*firewallMark));
    }
#else
    // Linux socket options
    if (bindInterface) {
        // Bind to specific interface
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
                   bindInterface->c_str(), bindInterface->size());
    }
    if (firewallMark) {
        // Set firewall mark
        setsockopt(fd, SOL_SOCKET, SO_MARK, firewallMark, sizeof(*firewallMark));
    }
#endif
}

} // namespace hy2::platform
