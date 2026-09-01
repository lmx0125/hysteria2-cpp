// http_server.hpp - HTTP CONNECT proxy server using Hysteria2 client as outbound.
// Rewrite of app/internal/http/server.go.
// Cross-platform: no platform-specific code.
#pragma once

#include <functional>
#include <memory>
#include <string>

#include "hy2/client.hpp"
#include "hy2/server_iface.hpp"

namespace hy2::proxy::http {

// EventLogger for HTTP proxy server events.
class IHttpEventLogger {
public:
    virtual ~IHttpEventLogger() = default;
    virtual void ConnectRequest(const std::string& addr, const std::string& reqAddr) {}
    virtual void ConnectError(const std::string& addr, const std::string& reqAddr,
                              const std::string& err) {}
    virtual void HTTPRequest(const std::string& addr, const std::string& url) {}
    virtual void HTTPError(const std::string& addr, const std::string& url,
                           const std::string& err) {}
};

// HttpServer is an HTTP CONNECT proxy server using a Hysteria2 client as outbound.
// Matches Go's app/internal/http/server.go behavior exactly.
class HttpServer {
public:
    std::shared_ptr<client::Client> HyClient;
    std::function<bool(const std::string&, const std::string&)> AuthFunc;
    std::string AuthRealm;
    IHttpEventLogger* EventLogger = nullptr;

    // Handle a single connection (dispatch loop for keep-alive).
    void dispatch(std::shared_ptr<server::IConn> conn);

private:
    bool handleConnect(std::shared_ptr<server::IConn> conn,
                       const std::string& targetAddr);
};

// Parse HTTP request line: "METHOD host:port HTTP/1.x"
// Returns the target address (host:port).
std::string parseHttpRequestTarget(const std::string& requestLine);

// Parse "Proxy-Authorization: Basic <base64>" header.
// Returns {username, password}. Empty if not present or invalid.
std::pair<std::string, std::string> parseProxyAuth(const std::string& header);

} // namespace hy2::proxy::http
