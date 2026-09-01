// udphop.hpp - Rewrite of extras/transport/udphop/addr.go (address
// parsing/formatting only; conn.go needs real sockets and is omitted).
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hy2::udphop {

// UDPHopAddr contains an IP address and a list of ports.
struct UDPHopAddr {
    std::string IP; // canonical textual IP (Go stores net.IP)
    std::vector<uint16_t> Ports;
    std::string PortStr;

    std::string Network() const { return "udphop"; }
    // Go: net.JoinHostPort(a.IP.String(), a.PortStr)
    std::string String() const;
    // One "ip:port" address per port (Go addrs()).
    std::vector<std::string> Addrs() const;
};

// ResolveUDPHopAddr parses "ip:portunion" into a UDPHopAddr. Only literal
// IPs are supported (no DNS). Throws hy2::Error with the Go-matching
// message on failure:
//   - "address <addr>: <why>"        (net.SplitHostPort failures)
//   - "<portStr> is not a valid port number or range"  (InvalidPortError)
UDPHopAddr ResolveUDPHopAddr(const std::string& addr);

} // namespace hy2
