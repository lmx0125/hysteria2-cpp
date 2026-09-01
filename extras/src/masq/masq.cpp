// masq.cpp - rewrite of extras/masq/server.go.
#include "hy2/masq/masq.hpp"

#include "hy2/error.hpp"

namespace hy2::masq {

namespace {

// Mirrors Go net/http's hexEscapeNonASCII (bytes >= 0x80 become %XX).
std::string hexEscapeNonASCII(const std::string& s) {
    static const char hex[] = "0123456789ABCDEF";
    std::string r;
    r.reserve(s.size());
    for (unsigned char c : s) {
        if (c < 0x80) {
            r += static_cast<char>(c);
        } else {
            r += '%';
            r += hex[(c >> 4) & 0xf];
            r += hex[c & 0xf];
        }
    }
    return r;
}

// Mirrors Go net/http's htmlEscape (& " ' < > and NUL; other bytes pass
// through unchanged).
std::string htmlEscape(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
        case 0: r += "\xEF\xBF\xBD"; break; // U+FFFD
        case '"': r += "&#34;"; break;
        case '&': r += "&amp;"; break;
        case '\'': r += "&#39;"; break;
        case '<': r += "&lt;"; break;
        case '>': r += "&gt;"; break;
        default: r += static_cast<char>(c);
        }
    }
    return r;
}

// Faithful subset of Go http.Redirect for absolute redirect URLs.
void httpRedirect(server::HttpResponseWriter& w, const server::HttpRequest& r,
                  const std::string& url, int code) {
    server::HeaderMap& h = w.Header();
    bool hadCT = h.find("Content-Type") != h.end();
    h["Location"] = hexEscapeNonASCII(url);
    if (r.Method == "GET" || r.Method == "HEAD") {
        h["Content-Type"] = "text/html; charset=utf-8";
    }
    w.WriteHeader(code);
    // Shouldn't send the body for POST or HEAD; that leaves GET.
    if (!hadCT && r.Method == "GET") {
        // statusText[301] == "Moved Permanently"; Fprintln adds one more "\n".
        std::string body =
            "<a href=\"" + htmlEscape(url) + "\">Moved Permanently</a>.\n";
        body += "\n";
        w.Write(reinterpret_cast<const uint8_t*>(body.data()), body.size());
    }
}

} // namespace

AltSvcHijackResponseWriter::AltSvcHijackResponseWriter(server::HttpResponseWriter& inner,
                                                       int port)
    : inner_(inner), port_(port) {}

void AltSvcHijackResponseWriter::WriteHeader(int statusCode) {
    inner_.Header()["Alt-Svc"] = "h3=\":" + std::to_string(port_) + "\"; ma=2592000";
    inner_.WriteHeader(statusCode);
}

void MasqTCPServer::serveWithAltSvc(server::HttpResponseWriter& w,
                                    const server::HttpRequest& r) const {
    AltSvcHijackResponseWriter wrapped(w, QUICPort);
    Handler->ServeHTTP(wrapped, r);
}

void MasqTCPServer::ServeHTTP(server::HttpResponseWriter& w,
                              const server::HttpRequest& r) const {
    if (ForceHTTPS) {
        const std::string& uri = r.Path; // RequestURI
        std::string loc;
        if (HTTPSPort == 0 || HTTPSPort == 443) {
            // Omit port if it's the default
            loc = "https://" + r.Host + uri;
        } else {
            loc = "https://" + r.Host + ":" + std::to_string(HTTPSPort) + uri;
        }
        httpRedirect(w, r, loc, 301); // http.StatusMovedPermanently
        return;
    }
    serveWithAltSvc(w, r);
}

} // namespace hy2::masq
