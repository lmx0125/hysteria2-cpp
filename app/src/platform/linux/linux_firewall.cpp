// linux_firewall.cpp - Linux firewall manager implementation.
// Uses iptables/nftables to set up UDP port redirect rules.

#ifdef __linux__

#include "hy2/platform/linux/linux_firewall.hpp"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

namespace hy2::platform::linux_impl {

LinuxFirewallManager::LinuxFirewallManager() {}

LinuxFirewallManager::~LinuxFirewallManager() {
    Cleanup();
}

bool LinuxFirewallManager::LookPath(const std::string& name) {
    std::string cmd = "which " + name + " 2>/dev/null";
    return system(cmd.c_str()) == 0;
}

bool LinuxFirewallManager::Run(const std::string& name, const std::vector<std::string>& args) {
    std::string cmd = name;
    for (const auto& arg : args) {
        cmd += " " + arg;
    }
    cmd += " 2>&1";
    int ret = system(cmd.c_str());
    return ret == 0;
}

bool LinuxFirewallManager::SetupUDPPortRedirect(const std::string& listenAddr,
                                                  uint16_t listenPort,
                                                  const std::vector<FirewallPortRange>& ports) {
    if (ports.empty()) return true;

    // Auto-detect backend: prefer nftables, fall back to iptables
    if (LookPath("nft")) {
        backend_ = "nftables";
        return SetupNFTablesRedirect(listenAddr, listenPort, ports);
    } else if (LookPath("iptables")) {
        backend_ = "iptables";
        return SetupIPTablesRedirect(listenAddr, listenPort, ports);
    }

    return false;
}

bool LinuxFirewallManager::SetupIPTablesRedirect(const std::string& listenAddr,
                                                   uint16_t listenPort,
                                                   const std::vector<FirewallPortRange>& ports) {
    // Generate unique chain name
    std::string chainName = "HYSTERIA-PR-" + std::to_string(getpid());

    // Create custom chain
    if (!Run("iptables", {"-t", "nat", "-N", chainName})) {
        return false;
    }
    createdChains_.push_back(chainName);

    // Add REDIRECT rule in custom chain
    std::string redirectTarget;
    if (listenAddr.empty() || listenAddr == "0.0.0.0") {
        redirectTarget = "REDIRECT --to-ports " + std::to_string(listenPort);
    } else {
        // DNAT for specific address
        redirectTarget = "DNAT --to-destination " + listenAddr + ":" + std::to_string(listenPort);
    }

    if (!Run("iptables", {"-t", "nat", "-A", chainName, "-p", "udp", "-j", redirectTarget})) {
        CleanupIPTables();
        return false;
    }

    // Add jump rules from PREROUTING and OUTPUT for each port range
    for (const auto& portRange : ports) {
        std::string portExpr;
        if (portRange.start == portRange.end) {
            portExpr = std::to_string(portRange.start);
        } else {
            portExpr = std::to_string(portRange.start) + ":" + std::to_string(portRange.end);
        }

        for (const auto& baseChain : {"PREROUTING", "OUTPUT"}) {
            std::vector<std::string> args = {
                "-t", "nat", "-A", baseChain,
                "-p", "udp", "--dport", portExpr,
                "-j", chainName
            };

            if (!listenAddr.empty() && listenAddr != "0.0.0.0") {
                args.insert(args.begin() + 4, "-d");
                args.insert(args.begin() + 5, listenAddr);
            }

            if (!Run("iptables", args)) {
                CleanupIPTables();
                return false;
            }
        }
    }

    return true;
}

bool LinuxFirewallManager::SetupNFTablesRedirect(const std::string& listenAddr,
                                                   uint16_t listenPort,
                                                   const std::vector<FirewallPortRange>& ports) {
    // Generate unique table name
    std::string tableName = "hysteria_" + std::to_string(getpid());

    // Determine address family
    std::string family = "ip";
    if (!listenAddr.empty() && listenAddr.find(':') != std::string::npos) {
        family = "ip6";
    }

    // Create table
    if (!Run("nft", {"add", "table", family, tableName})) {
        return false;
    }
    createdTables_.push_back(tableName);

    // Create prerouting and output chains
    std::string chainDef = "{ type nat hook prerouting priority -100; policy accept; }";
    if (!Run("nft", {"add", "chain", family, tableName, "prerouting", chainDef})) {
        CleanupNFTables();
        return false;
    }

    chainDef = "{ type nat hook output priority -100; policy accept; }";
    if (!Run("nft", {"add", "chain", family, tableName, "output", chainDef})) {
        CleanupNFTables();
        return false;
    }

    // Add redirect rules for each port range
    for (const auto& portRange : ports) {
        std::string portExpr;
        if (portRange.start == portRange.end) {
            portExpr = std::to_string(portRange.start);
        } else {
            portExpr = std::to_string(portRange.start) + "-" + std::to_string(portRange.end);
        }

        for (const auto& chain : {"prerouting", "output"}) {
            std::string target;
            if (family == "ip6" && !listenAddr.empty() && listenAddr != "0.0.0.0") {
                // IPv6 with specific address uses DNAT
                target = "dnat to [" + listenAddr + "]:" + std::to_string(listenPort);
            } else {
                // IPv4 or wildcard uses redirect
                target = "redirect to :" + std::to_string(listenPort);
            }

            std::vector<std::string> args = {
                "add", "rule", family, tableName, std::string(chain),
                "udp", "dport", portExpr, target
            };

            if (!listenAddr.empty() && listenAddr != "0.0.0.0") {
                args.insert(args.begin() + 4, family == "ip6" ? "ip6" : "ip");
                args.insert(args.begin() + 5, "daddr");
                args.insert(args.begin() + 6, listenAddr);
            }

            if (!Run("nft", args)) {
                CleanupNFTables();
                return false;
            }
        }
    }

    return true;
}

void LinuxFirewallManager::Cleanup() {
    CleanupIPTables();
    CleanupNFTables();
}

void LinuxFirewallManager::CleanupIPTables() {
    for (const auto& chainName : createdChains_) {
        Run("iptables", {"-t", "nat", "-F", chainName});
        Run("iptables", {"-t", "nat", "-X", chainName});
    }
    createdChains_.clear();
}

void LinuxFirewallManager::CleanupNFTables() {
    for (const auto& tableName : createdTables_) {
        // Determine family from table name (simplified)
        std::string family = "ip";
        Run("nft", {"delete", "table", family, tableName});
    }
    createdTables_.clear();
}

} // namespace hy2::platform::linux_impl

#endif // __linux__
