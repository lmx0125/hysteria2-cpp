// win_firewall.hpp - Windows firewall manager implementation.
// Uses Windows Filtering Platform (WFP) for packet redirection.
// Provides equivalent functionality to Linux iptables/nftables.
#pragma once

#ifdef _WIN32

#include "hy2/platform/platform_common.hpp"

#include <string>
#include <vector>

namespace hy2::platform::windows_impl {

// WindowsFirewallManager - Manages WFP rules for UDP port redirect.
// Uses WFP callout drivers to intercept and redirect packets.
class WindowsFirewallManager : public IFirewallManager {
public:
    WindowsFirewallManager();
    ~WindowsFirewallManager() override;

    bool SetupUDPPortRedirect(const std::string& listenAddr,
                               uint16_t listenPort,
                               const std::vector<FirewallPortRange>& ports) override;
    void Cleanup() override;

private:
    bool SetupWFPRedirect(const std::string& listenAddr,
                           uint16_t listenPort,
                           const std::vector<FirewallPortRange>& ports);

    void* engineHandle_ = nullptr;  // FWPM_ENGINE_HANDLE
    uint64_t addedFilterId_ = 0;
};

} // namespace hy2::platform::windows_impl

#endif // _WIN32
