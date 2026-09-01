// masq.hpp - Rewrite of extras/masq/server.go (handler logic only; the
// TCP/TLS listeners need real sockets and are omitted).
#pragma once

#include <memory>

#include "hy2/server_iface.hpp"

namespace hy2::masq {

// AltSvcHijackResponseWriter makes sure that the Alt-Svc's port is always
// set with our own value, no matter what the handler sets.
// (Go's Hijacker wrapper variant is WebSocket-specific and has no
// equivalent here.)
class AltSvcHijackResponseWriter : public server::HttpResponseWriter {
public:
    explicit AltSvcHijackResponseWriter(server::HttpResponseWriter& inner, int port);

    server::HeaderMap& Header() override { return inner_.Header(); }
    void WriteHeader(int statusCode) override;
    void Write(const uint8_t* p, size_t n) override { inner_.Write(p, n); }

private:
    server::HttpResponseWriter& inner_;
    int port_;
};

// MasqTCPServer covers the TCP parts of a standard web server (TCP based
// HTTP/HTTPS). We provide this as an option for masquerading, as some may
// consider a server "suspicious" if it only serves the QUIC protocol and not
// standard HTTP/HTTPS.
struct MasqTCPServer {
    int QUICPort = 0;
    int HTTPSPort = 0;
    // Handler serves the actual content (Go http.Handler).
    std::shared_ptr<server::IHttpHandler> Handler;
    bool ForceHTTPS = false; // Always 301 redirect from HTTP to HTTPS

    // ServeHTTP handles one request. The Go version wires this into
    // ListenAndServeHTTP / ListenAndServeHTTPS (real sockets + TLS omitted).
    void ServeHTTP(server::HttpResponseWriter& w, const server::HttpRequest& r) const;

private:
    void serveWithAltSvc(server::HttpResponseWriter& w, const server::HttpRequest& r) const;
};

} // namespace hy2::masq
