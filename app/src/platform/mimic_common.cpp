// mimic_common.cpp - Shared mimic types and configuration.

#include "hy2/platform/mimic_common.hpp"

#include <algorithm>
#include <sstream>

namespace hy2::platform {

std::vector<std::string> GenerateMimicFilters(MimicRole role,
                                               const std::vector<std::string>& addresses) {
    std::vector<std::string> filters;
    std::vector<std::string> seen;

    if (role == MimicRole::Client) {
        // Client filters: remote=<host>:<port>
        for (const auto& addr : addresses) {
            std::string filter = "remote=" + addr;
            if (std::find(seen.begin(), seen.end(), filter) == seen.end()) {
                seen.push_back(filter);
                filters.push_back(filter);
            }
        }
    } else {
        // Server filters: local=<host>:<port>,handshake=0:3
        for (const auto& addr : addresses) {
            std::string filter = "local=" + addr + ",handshake=0:3";
            if (std::find(seen.begin(), seen.end(), filter) == seen.end()) {
                seen.push_back(filter);
                filters.push_back(filter);
            }
        }
    }

    return filters;
}

std::string ParseFilterAddress(const std::string& filter) {
    // Extract address from filter string
    // "remote=192.168.1.1:443" -> "192.168.1.1:443"
    // "local=0.0.0.0:8080,handshake=0:3" -> "0.0.0.0:8080"
    // "remote=[2001:db8::1]:443" -> "2001:db8::1:443"
    // "local=[::]:8080,handshake=0:3" -> ":::8080"

    auto eqPos = filter.find('=');
    if (eqPos == std::string::npos) return "";

    auto commaPos = filter.find(',', eqPos);
    std::string addr;
    if (commaPos == std::string::npos) {
        addr = filter.substr(eqPos + 1);
    } else {
        addr = filter.substr(eqPos + 1, commaPos - eqPos - 1);
    }

    // Strip brackets from IPv6 addresses like [2001:db8::1]:port or [::]:port
    if (addr.size() > 2 && addr.front() == '[') {
        auto closeBracket = addr.find(']');
        if (closeBracket != std::string::npos) {
            // Remove '[' and ']', keep everything else including :port
            addr = addr.substr(1, closeBracket - 1) + addr.substr(closeBracket + 1);
        }
    }

    return addr;
}

} // namespace hy2::platform
