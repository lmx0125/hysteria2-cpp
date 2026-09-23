// direct.hpp - Direct outbound: TCP/UDP dial using OS sockets.
// Rewrite of extras/outbounds/ob_direct.go.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "hy2/server_iface.hpp"

namespace hy2::outbounds {

enum class DirectOutboundMode : int {
    Auto = 0, // Dual-stack happy eyeballs
    IPv6Prefer = 1, // 64: prefer IPv6, fallback IPv4
    IPv4Prefer = 2, // 46: prefer IPv4, fallback IPv6
    IPv6Only = 3,   // 6: IPv6 only
    IPv4Only = 4,   // 4: IPv4 only
};

// DirectOutbound dials TCP/UDP targets directly using OS sockets.
// Matches Go's directOutbound behavior.
class DirectOutbound : public server::Outbound {
public:
    explicit DirectOutbound(DirectOutboundMode mode = DirectOutboundMode::Auto);

    std::shared_ptr<server::IConn> TCP(const std::string& reqAddr) override;
    std::shared_ptr<server::IUdpConn> UDP(const std::string& reqAddr) override;
    bool CheckUDP(const std::string& reqAddr) override;

private:
    DirectOutboundMode mode_;
};

// Test hook: how many times the UDP send path has called getaddrinfo().
// A session's destination is resolved once and then cached, so this should
// grow by at most one per distinct target no matter how many datagrams are
// sent. Used by DirectOutboundUdp* tests to catch a regression back to
// per-datagram resolution.
uint64_t DirectOutboundUdpResolveCount();

} // namespace hy2::outbounds
