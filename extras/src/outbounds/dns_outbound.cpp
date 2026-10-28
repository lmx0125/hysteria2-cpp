// dns_outbound.cpp - DNS resolver for outbound ACL routing.
// Rewrite of extras/outbounds/dns_standard.go + dns_system.go + dns_https.go.
#include "hy2/outbounds/dns_outbound.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#if __has_include(<openssl/ssl.h>)
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/x509v3.h>
  #define HY2_OPENSSL_AVAILABLE 1
#else
  #define HY2_OPENSSL_AVAILABLE 0
#endif

namespace hy2::outbounds {

// ---------------------------------------------------------------------------
// SystemDnsResolver - uses getaddrinfo

DnsResult SystemDnsResolver::Resolve(const std::string& hostname) {
    DnsResult result;

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) {
        result.error = gai_strerror(rc);
        return result;
    }

    for (auto* rp = res; rp != nullptr; rp = rp->ai_next) {
        char ip[INET6_ADDRSTRLEN] = {};
        if (rp->ai_family == AF_INET && !result.hasIpv4) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            result.ipv4 = ip;
            result.hasIpv4 = true;
        } else if (rp->ai_family == AF_INET6 && !result.hasIpv6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
            result.ipv6 = ip;
            result.hasIpv6 = true;
        }
        if (result.hasIpv4 && result.hasIpv6) break;
    }
    freeaddrinfo(res);
    return result;
}

// ---------------------------------------------------------------------------
// StandardDnsResolver - UDP/TCP DNS query (RFC 1035)

StandardDnsResolver::StandardDnsResolver(const std::string& serverAddr, bool useTcp)
    : serverAddr_(serverAddr), useTcp_(useTcp) {}

DnsResult StandardDnsResolver::Resolve(const std::string& hostname) {
    DnsResult result;

    // Build DNS query for A and AAAA records
    std::vector<uint8_t> query;

    // Transaction ID
    uint16_t txid = 0x1234;
    query.push_back(static_cast<uint8_t>((txid >> 8) & 0xFF));
    query.push_back(static_cast<uint8_t>(txid & 0xFF));

    // Flags: standard query, recursion desired
    query.push_back(0x01);
    query.push_back(0x00);

    // Questions: 2 (A + AAAA)
    query.push_back(0x00);
    query.push_back(0x02);

    // Answer/Auth/Additional counts: 0
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);

    // Encode hostname as DNS name
    auto encodeName = [&query](const std::string& name) {
        size_t start = 0;
        while (start < name.size()) {
            auto dot = name.find('.', start);
            size_t len = (dot == std::string::npos) ? name.size() - start : dot - start;
            query.push_back(static_cast<uint8_t>(len));
            query.insert(query.end(), name.begin() + start, name.begin() + start + len);
            start += len + 1;
        }
        query.push_back(0x00); // root label
    };

    encodeName(hostname);

    // A record query (type 1, class IN)
    query.push_back(0x00);
    query.push_back(0x01); // type A
    query.push_back(0x00);
    query.push_back(0x01); // class IN

    encodeName(hostname);

    // AAAA record query (type 28, class IN)
    query.push_back(0x00);
    query.push_back(0x1C); // type AAAA
    query.push_back(0x00);
    query.push_back(0x01); // class IN

    // Parse server address
    auto colon = serverAddr_.rfind(':');
    if (colon == std::string::npos) {
        result.error = "invalid DNS server address";
        return result;
    }
    std::string serverHost = serverAddr_.substr(0, colon);
    uint16_t serverPort = static_cast<uint16_t>(std::atoi(serverAddr_.c_str() + colon + 1));

    // Connect to DNS server
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = useTcp_ ? SOCK_STREAM : SOCK_DGRAM;

    struct addrinfo* res = nullptr;
    std::string portStr = std::to_string(serverPort);
    if (getaddrinfo(serverHost.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        result.error = "failed to resolve DNS server";
        return result;
    }

    // SOCKET is pointer-sized on Windows; narrowing it to int can truncate it.
    const auto fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
#ifdef _WIN32
    const bool invalidSocket = fd == INVALID_SOCKET;
#else
    const bool invalidSocket = fd < 0;
#endif
    if (invalidSocket) {
        freeaddrinfo(res);
        result.error = "failed to create socket";
        return result;
    }

    if (::connect(fd, res->ai_addr, static_cast<int>(res->ai_addrlen)) < 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        freeaddrinfo(res);
        result.error = "failed to connect to DNS server";
        return result;
    }
    freeaddrinfo(res);

    // For TCP, prepend 2-byte length
    std::vector<uint8_t> wireQuery;
    if (useTcp_) {
        uint16_t len = static_cast<uint16_t>(query.size());
        wireQuery.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        wireQuery.push_back(static_cast<uint8_t>(len & 0xFF));
    }
    wireQuery.insert(wireQuery.end(), query.begin(), query.end());

    // Send query
    ::send(fd, reinterpret_cast<const char*>(wireQuery.data()),
           static_cast<int>(wireQuery.size()), 0);

    // An unreachable/silent DNS server must not park this caller forever.
    // select bounds the response wait on both UDP and TCP without depending
    // on platform-specific SO_RCVTIMEO units.
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(fd, &readable);
    timeval responseTimeout{3, 0};
#ifdef _WIN32
    const int ready = ::select(0, &readable, nullptr, nullptr, &responseTimeout);
#else
    const int ready = ::select(fd + 1, &readable, nullptr, nullptr, &responseTimeout);
#endif
    if (ready <= 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        result.error = ready == 0 ? "DNS response timeout" : "DNS response wait failed";
        return result;
    }

    // Read response
    std::vector<uint8_t> response(4096);
    int n = static_cast<int>(::recv(fd, reinterpret_cast<char*>(response.data()),
                                    static_cast<int>(response.size()), 0));
#ifdef _WIN32
    closesocket(fd);
#else
    ::close(fd);
#endif

    if (n < 12) {
        result.error = "DNS response too short";
        return result;
    }

    // Skip header (12 bytes)
    size_t pos = 12;

    // Skip questions
    uint16_t qdcount = (static_cast<uint16_t>(response[4]) << 8) | response[5];
    for (uint16_t i = 0; i < qdcount && pos < response.size(); i++) {
        // Skip name
        while (pos < response.size() && response[pos] != 0) {
            if ((response[pos] & 0xC0) == 0xC0) { pos += 2; break; }
            pos += response[pos] + 1;
        }
        if (pos < response.size() && response[pos] == 0) pos++;
        pos += 4; // type + class
    }

    // Read answers
    uint16_t ancount = (static_cast<uint16_t>(response[6]) << 8) | response[7];
    for (uint16_t i = 0; i < ancount && pos < response.size(); i++) {
        // Skip name (may be compressed)
        if ((response[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < response.size() && response[pos] != 0) {
                pos += response[pos] + 1;
            }
            if (pos < response.size()) pos++;
        }

        if (pos + 10 > response.size()) break;

        uint16_t type = (static_cast<uint16_t>(response[pos]) << 8) | response[pos + 1];
        pos += 2; // type
        pos += 2; // class
        pos += 4; // TTL
        uint16_t rdlength = (static_cast<uint16_t>(response[pos]) << 8) | response[pos + 1];
        pos += 2; // rdlength

        if (pos + rdlength > response.size()) break;

        if (type == 1 && rdlength == 4 && !result.hasIpv4) {
            // A record
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, response.data() + pos, ip, sizeof(ip));
            result.ipv4 = ip;
            result.hasIpv4 = true;
        } else if (type == 28 && rdlength == 16 && !result.hasIpv6) {
            // AAAA record
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, response.data() + pos, ip, sizeof(ip));
            result.ipv6 = ip;
            result.hasIpv6 = true;
        }

        pos += rdlength;
    }

    if (!result.hasIpv4 && !result.hasIpv6) {
        result.error = "no records found";
    }

    return result;
}

// ---------------------------------------------------------------------------
// DohDnsResolver - DNS over HTTPS (RFC 8484)

#if HY2_OPENSSL_AVAILABLE

namespace {

// URL parsing helper
struct ParsedUrl {
    std::string host;
    uint16_t port = 443;
    std::string path;
    bool useTls = true;
};

ParsedUrl parseUrl(const std::string& url) {
    ParsedUrl result;
    std::string rest = url;

    // Remove scheme
    if (rest.find("https://") == 0) {
        rest = rest.substr(8);
        result.useTls = true;
    } else if (rest.find("http://") == 0) {
        rest = rest.substr(7);
        result.useTls = false;
        result.port = 80;
    }

    // Extract path
    auto slashPos = rest.find('/');
    if (slashPos != std::string::npos) {
        result.path = rest.substr(slashPos);
        rest = rest.substr(0, slashPos);
    } else {
        result.path = "/dns-query";
    }

    // Extract host:port
    auto colonPos = rest.rfind(':');
    if (colonPos != std::string::npos) {
        result.host = rest.substr(0, colonPos);
        result.port = static_cast<uint16_t>(std::atoi(rest.c_str() + colonPos + 1));
    } else {
        result.host = rest;
        if (result.useTls) {
            result.port = 443;
        } else {
            result.port = 80;
        }
    }

    return result;
}

// Base64url encoding for DoH
static const char kBase64UrlChars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64UrlEncode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        result.push_back(kBase64UrlChars[(n >> 18) & 0x3F]);
        result.push_back(kBase64UrlChars[(n >> 12) & 0x3F]);
        if (i + 1 < len) result.push_back(kBase64UrlChars[(n >> 6) & 0x3F]);
        if (i + 2 < len) result.push_back(kBase64UrlChars[n & 0x3F]);
    }
    return result;
}

// HTTPS request using OpenSSL
std::string httpsRequest(const std::string& host, uint16_t port,
                         const std::string& path, const std::string& sni,
                         bool insecure, const uint8_t* body, size_t bodyLen,
                         bool isPost) {
    // Resolve host
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        return "";
    }

    // Create socket
    int fd = static_cast<int>(socket(res->ai_family, res->ai_socktype, res->ai_protocol));
    if (fd < 0) {
        freeaddrinfo(res);
        return "";
    }

    // Connect
    if (::connect(fd, res->ai_addr, static_cast<int>(res->ai_addrlen)) < 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        freeaddrinfo(res);
        return "";
    }
    freeaddrinfo(res);

    // Create SSL context
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        return "";
    }

    if (insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_default_verify_paths(ctx);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    // Set SNI for TLS handshake (using SSL_ctrl to avoid const-cast issues)
    SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name,
             const_cast<char*>(sni.empty() ? host.c_str() : sni.c_str()));

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        return "";
    }

    // Build HTTP request
    std::stringstream req;
    if (isPost) {
        req << "POST " << path << " HTTP/1.1\r\n";
        req << "Host: " << host << "\r\n";
        req << "Content-Type: application/dns-message\r\n";
        req << "Content-Length: " << bodyLen << "\r\n";
    } else {
        std::string encodedQuery = base64UrlEncode(body, bodyLen);
        req << "GET " << path << "?dns=" << encodedQuery << " HTTP/1.1\r\n";
        req << "Host: " << host << "\r\n";
    }
    req << "Accept: application/dns-message\r\n";
    req << "Connection: close\r\n";
    req << "\r\n";

    std::string reqStr = req.str();
    SSL_write(ssl, reqStr.c_str(), static_cast<int>(reqStr.size()));
    if (isPost && body && bodyLen > 0) {
        SSL_write(ssl, body, static_cast<int>(bodyLen));
    }

    // Read response
    std::string response;
    char buf[4096];
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        response.append(buf, n);
    }

    SSL_free(ssl);
    SSL_CTX_free(ctx);
#ifdef _WIN32
    closesocket(fd);
#else
    ::close(fd);
#endif

    // Extract body (after double CRLF)
    auto bodyStart = response.find("\r\n\r\n");
    if (bodyStart == std::string::npos) {
        return "";
    }
    return response.substr(bodyStart + 4);
}

} // anonymous namespace

DohDnsResolver::DohDnsResolver(const std::string& dohUrl,
                               const std::string& sni,
                               bool insecure)
    : dohUrl_(dohUrl), sni_(sni), insecure_(insecure) {}

std::vector<uint8_t> DohDnsResolver::buildQuery(const std::string& hostname) {
    std::vector<uint8_t> query;

    // Transaction ID
    uint16_t txid = 0x5678;
    query.push_back(static_cast<uint8_t>((txid >> 8) & 0xFF));
    query.push_back(static_cast<uint8_t>(txid & 0xFF));

    // Flags: standard query, recursion desired
    query.push_back(0x01);
    query.push_back(0x00);

    // Questions: 2 (A + AAAA)
    query.push_back(0x00);
    query.push_back(0x02);

    // Answer/Auth/Additional counts: 0
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);
    query.push_back(0x00);

    // Encode hostname as DNS name
    auto encodeName = [&query](const std::string& name) {
        size_t start = 0;
        while (start < name.size()) {
            auto dot = name.find('.', start);
            size_t len = (dot == std::string::npos) ? name.size() - start : dot - start;
            query.push_back(static_cast<uint8_t>(len));
            query.insert(query.end(), name.begin() + start, name.begin() + start + len);
            start += len + 1;
        }
        query.push_back(0x00); // root label
    };

    encodeName(hostname);

    // A record query (type 1, class IN)
    query.push_back(0x00);
    query.push_back(0x01); // type A
    query.push_back(0x00);
    query.push_back(0x01); // class IN

    encodeName(hostname);

    // AAAA record query (type 28, class IN)
    query.push_back(0x00);
    query.push_back(0x1C); // type AAAA
    query.push_back(0x00);
    query.push_back(0x01); // class IN

    return query;
}

DnsResult DohDnsResolver::parseResponse(const std::vector<uint8_t>& response) {
    DnsResult result;

    if (response.size() < 12) {
        result.error = "DNS response too short";
        return result;
    }

    // Skip header (12 bytes)
    size_t pos = 12;

    // Skip questions
    uint16_t qdcount = (static_cast<uint16_t>(response[4]) << 8) | response[5];
    for (uint16_t i = 0; i < qdcount && pos < response.size(); i++) {
        while (pos < response.size() && response[pos] != 0) {
            if ((response[pos] & 0xC0) == 0xC0) { pos += 2; break; }
            pos += response[pos] + 1;
        }
        if (pos < response.size() && response[pos] == 0) pos++;
        pos += 4; // type + class
    }

    // Read answers
    uint16_t ancount = (static_cast<uint16_t>(response[6]) << 8) | response[7];
    for (uint16_t i = 0; i < ancount && pos < response.size(); i++) {
        // Skip name (may be compressed)
        if ((response[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < response.size() && response[pos] != 0) {
                pos += response[pos] + 1;
            }
            if (pos < response.size()) pos++;
        }

        if (pos + 10 > response.size()) break;

        uint16_t type = (static_cast<uint16_t>(response[pos]) << 8) | response[pos + 1];
        pos += 2; // type
        pos += 2; // class
        pos += 4; // TTL
        uint16_t rdlength = (static_cast<uint16_t>(response[pos]) << 8) | response[pos + 1];
        pos += 2; // rdlength

        if (pos + rdlength > response.size()) break;

        if (type == 1 && rdlength == 4 && !result.hasIpv4) {
            // A record
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, response.data() + pos, ip, sizeof(ip));
            result.ipv4 = ip;
            result.hasIpv4 = true;
        } else if (type == 28 && rdlength == 16 && !result.hasIpv6) {
            // AAAA record
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, response.data() + pos, ip, sizeof(ip));
            result.ipv6 = ip;
            result.hasIpv6 = true;
        }

        pos += rdlength;
    }

    if (!result.hasIpv4 && !result.hasIpv6) {
        result.error = "no records found";
    }

    return result;
}

DnsResult DohDnsResolver::Resolve(const std::string& hostname) {
    DnsResult result;

    // Build DNS query
    auto query = buildQuery(hostname);

    // Parse DoH URL
    auto url = parseUrl(dohUrl_);

    // Try POST method first (RFC 8484 preferred)
    std::string responseBody = httpsRequest(
        url.host, url.port, url.path,
        sni_, insecure_,
        query.data(), query.size(),
        true  // POST
    );

    // Fall back to GET method if POST fails
    if (responseBody.empty()) {
        responseBody = httpsRequest(
            url.host, url.port, url.path,
            sni_, insecure_,
            query.data(), query.size(),
            false  // GET
        );
    }

    if (responseBody.empty()) {
        result.error = "DoH request failed";
        return result;
    }

    // Parse DNS response
    std::vector<uint8_t> response(responseBody.begin(), responseBody.end());
    return parseResponse(response);
}

#else // !HY2_OPENSSL_AVAILABLE

DohDnsResolver::DohDnsResolver(const std::string& /*dohUrl*/,
                               const std::string& /*sni*/,
                               bool /*insecure*/) {}

std::vector<uint8_t> DohDnsResolver::buildQuery(const std::string& /*hostname*/) {
    return {};
}

DnsResult DohDnsResolver::parseResponse(const std::vector<uint8_t>& /*response*/) {
    DnsResult result;
    result.error = "DoH not available (OpenSSL not installed)";
    return result;
}

DnsResult DohDnsResolver::Resolve(const std::string& /*hostname*/) {
    DnsResult result;
    result.error = "DoH not available (OpenSSL not installed)";
    return result;
}

#endif // HY2_OPENSSL_AVAILABLE

} // namespace hy2::outbounds
