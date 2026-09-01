// linux_firewall.hpp - Linux firewall manager implementation.
// Uses iptables/nftables to set up UDP port redirect rules.
#pragma once

#ifdef __linux__

#include "hy2/platform/platform_common.hpp"

#include <memory>
#include <string>
#include <vector>

namespace hy2::platform::linux_impl {

// LinuxFirewallManager - Manages iptables/nftables rules for UDP port redirect.
class LinuxFirewallManager : public IFirewallManager {
public:
    LinuxFirewallManager();
    ~LinuxFirewallManager() override;

    bool SetupUDPPortRedirect(const std::string& listenAddr,
                               uint16_t listenPort,
                               const std::vector<FirewallPortRange>& ports) override;
    void Cleanup() override;

private:
    // Command runner abstraction for testing
    virtual bool LookPath(const std::string& name);
    virtual bool Run(const std::string& name, const std::vector<std::string>& args);

    // Backend selection
    bool SetupIPTablesRedirect(const std::string& listenAddr,
                                uint16_t listenPort,
                                const std::vector<FirewallPortRange>& ports);
    bool SetupNFTablesRedirect(const std::string& listenAddr,
                                uint16_t listenPort,
                                const std::vector<FirewallPortRange>& ports);

    // Cleanup helpers
    void CleanupIPTables();
    void CleanupNFTables();

    // Generated rule names for cleanup
    std::vector<std::string> createdChains_;
    std::vector<std::string> createdTables_;
    std::string backend_;  // "iptables" or "nftables"
};

} // namespace hy2::platform::linux_impl

#endif // __linux__
