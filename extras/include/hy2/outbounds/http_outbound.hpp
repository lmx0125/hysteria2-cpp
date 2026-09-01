// http_outbound.hpp - HTTP CONNECT outbound proxy.
// Rewrite of extras/outbounds/ob_http.go.
#pragma once

#include <memory>
#include <string>

#include "hy2/server_iface.hpp"

namespace hy2::outbounds {

// HttpOutbound connects to targets via an HTTP/HTTPS CONNECT proxy.
// UDP is not supported (returns error), matching Go's behavior.
class HttpOutbound : public server::Outbound {
public:
    // proxyURL: "http://proxy:8080" or "https://proxy:443"
    // user/pass: optional basic auth credentials
    HttpOutbound(const std::string& proxyAddr, bool https = false,
                 const std::string& serverName = "",
                 bool insecureSkipVerify = false,
                 const std::string& user = "", const std::string& pass = "");

    std::shared_ptr<server::IConn> TCP(const std::string& reqAddr) override;
    std::shared_ptr<server::IUdpConn> UDP(const std::string& reqAddr) override;
    bool CheckUDP(const std::string& reqAddr) override;

private:
    std::string proxyAddr_;
    bool https_;
    std::string serverName_;
    bool insecureSkipVerify_;
    std::string basicAuth_; // "Basic <base64>" or empty
};

} // namespace hy2::outbounds
