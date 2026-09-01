// socks5_outbound.hpp - SOCKS5 outbound proxy.
// Rewrite of extras/outbounds/ob_socks5.go.
#pragma once

#include <memory>
#include <string>

#include "hy2/server_iface.hpp"

namespace hy2::outbounds {

// Socks5Outbound connects to targets via a SOCKS5 proxy.
class Socks5Outbound : public server::Outbound {
public:
    Socks5Outbound(const std::string& addr,
                   const std::string& username = "",
                   const std::string& password = "");

    std::shared_ptr<server::IConn> TCP(const std::string& reqAddr) override;
    std::shared_ptr<server::IUdpConn> UDP(const std::string& reqAddr) override;
    bool CheckUDP(const std::string& reqAddr) override;

private:
    // Connect + negotiate auth
    std::shared_ptr<server::IConn> dialAndNegotiate();
    // Send SOCKS5 request, returns the reply address for UDP ASSOCIATE
    std::string sendRequest(server::IConn& conn, uint8_t cmd,
                            const std::string& targetAddr);

    std::string addr_;
    std::string username_;
    std::string password_;
};

} // namespace hy2::outbounds
