// udphop.cpp - rewrite of extras/transport/udphop/addr.go.
#include "hy2/udphop/udphop.hpp"

#include "hy2/error.hpp"
#include "hy2/netaddr.hpp"
#include "hy2/portunion.hpp"

namespace hy2::udphop {

std::string UDPHopAddr::String() const { return JoinHostPort(IP, PortStr); }

std::vector<std::string> UDPHopAddr::Addrs() const {
    std::vector<std::string> addrs;
    addrs.reserve(Ports.size());
    for (uint16_t port : Ports) {
        addrs.push_back(JoinHostPort(IP, std::to_string(port)));
    }
    return addrs;
}

UDPHopAddr ResolveUDPHopAddr(const std::string& addr) {
    std::string msg;
    auto hp = SplitHostPort(addr, msg);
    if (!hp) {
        throw Error(msg);
    }
    const std::string& host = hp->first;
    const std::string& portStr = hp->second;

    // Go: net.ResolveIPAddr("ip", host) resolves names too; we support
    // literal IPs only.
    std::string ip = CanonicalizeIP(host);
    if (ip.empty()) {
        throw Error("lookup " + host + ": no such host");
    }

    UDPHopAddr result;
    result.IP = std::move(ip);
    result.PortStr = portStr;

    bool ok = false;
    PortUnion pu = ParsePortUnion(portStr, ok);
    if (!ok) {
        throw Error(portStr + " is not a valid port number or range");
    }
    result.Ports = PortUnionPorts(pu);

    return result;
}

} // namespace hy2::udphop
