// http_outbound.cpp - HTTP CONNECT outbound proxy.
// Rewrite of extras/outbounds/ob_http.go.
#include "hy2/outbounds/http_outbound.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <vector>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#if __has_include(<openssl/ssl.h>)
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #define HY2_OPENSSL_AVAILABLE 1
#else
  #define HY2_OPENSSL_AVAILABLE 0
#endif

namespace hy2::outbounds {

namespace {

constexpr int kConnectTimeoutSec = 10;
constexpr int kResponseTimeoutSec = 10;

// Base64 encoding
static const char kBase64Table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::string& input) {
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(kBase64Table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) output.push_back(kBase64Table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (output.size() % 4) output.push_back('=');
    return output;
}

// TCP connection wrapper (raw socket)
class RawTcpConn : public server::IConn {
public:
    explicit RawTcpConn(int fd) : fd_(fd) {}
    ~RawTcpConn() override { Close(); }

    size_t Read(uint8_t* p, size_t n) override {
        if (fd_ < 0) return 0;
        int r = static_cast<int>(::recv(fd_, reinterpret_cast<char*>(p),
                                        static_cast<int>(n), 0));
        return r <= 0 ? 0 : static_cast<size_t>(r);
    }

    void Write(const uint8_t* p, size_t n) override {
        if (fd_ < 0) throw std::runtime_error("http outbound: conn closed");
        size_t off = 0;
        while (off < n) {
            int w = static_cast<int>(::send(fd_,
                                            reinterpret_cast<const char*>(p + off),
                                            static_cast<int>(n - off), 0));
            if (w <= 0) throw std::runtime_error("http outbound: send failed");
            off += static_cast<size_t>(w);
        }
    }

    void Close() override {
        if (fd_ >= 0) {
#ifdef _WIN32
            closesocket(fd_);
#else
            ::close(fd_);
#endif
            fd_ = -1;
        }
    }

    int fd() const { return fd_; }

private:
    int fd_ = -1;
};

// TLS connection wrapper using OpenSSL
#if HY2_OPENSSL_AVAILABLE
class TlsTcpConn : public server::IConn {
public:
    TlsTcpConn(int fd, const std::string& serverName, bool insecure)
        : fd_(fd), ctx_(nullptr), ssl_(nullptr) {
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_) throw std::runtime_error("TLS: failed to create context");
        if (insecure) {
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_NONE, nullptr);
        }
        ssl_ = SSL_new(ctx_);
        if (!ssl_) throw std::runtime_error("TLS: failed to create SSL");
        SSL_set_fd(ssl_, fd);
        if (!serverName.empty()) {
            SSL_set_tlsext_host_name(ssl_, serverName.c_str());
        }
        if (SSL_connect(ssl_) <= 0) {
            throw std::runtime_error("TLS: handshake failed");
        }
    }

    ~TlsTcpConn() override { Close(); }

    size_t Read(uint8_t* p, size_t n) override {
        if (!ssl_) return 0;
        int r = SSL_read(ssl_, p, static_cast<int>(n));
        return r <= 0 ? 0 : static_cast<size_t>(r);
    }

    void Write(const uint8_t* p, size_t n) override {
        if (!ssl_) throw std::runtime_error("TLS conn closed");
        int w = SSL_write(ssl_, p, static_cast<int>(n));
        if (w <= 0) throw std::runtime_error("TLS write failed");
    }

    void Close() override {
        if (ssl_) { SSL_free(ssl_); ssl_ = nullptr; }
        if (ctx_) { SSL_CTX_free(ctx_); ctx_ = nullptr; }
        if (fd_ >= 0) {
#ifdef _WIN32
            closesocket(fd_);
#else
            ::close(fd_);
#endif
            fd_ = -1;
        }
    }

private:
    int fd_;
    SSL_CTX* ctx_;
    SSL* ssl_;
};
#endif // HY2_OPENSSL_AVAILABLE

// Read line from a raw connection (for HTTP response parsing)
std::string readLine(server::IConn& conn) {
    std::string line;
    char c;
    while (true) {
        size_t n = conn.Read(reinterpret_cast<uint8_t*>(&c), 1);
        if (n == 0) break;
        if (c == '\n') break;
        if (c != '\r') line.push_back(c);
    }
    return line;
}

// Connect to proxy
int dialProxy(const std::string& addr) {
    auto colon = addr.rfind(':');
    if (colon == std::string::npos) return -1;
    std::string host = addr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(addr.c_str() + colon + 1));

    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) return -1;

    int fd = static_cast<int>(socket(res->ai_family, res->ai_socktype, res->ai_protocol));
    if (fd < 0) { freeaddrinfo(res); return -1; }

#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(fd, FIONBIO, &nb);
    int rc = ::connect(fd, res->ai_addr, static_cast<int>(res->ai_addrlen));
    if (rc < 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        freeaddrinfo(res); closesocket(fd); return -1;
    }
    fd_set wf; FD_ZERO(&wf); FD_SET(static_cast<SOCKET>(fd), &wf);
    struct timeval tv{kConnectTimeoutSec, 0};
    if (select(0, nullptr, &wf, nullptr, &tv) <= 0) {
        freeaddrinfo(res); closesocket(fd); return -1;
    }
    int err = 0; int len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
    if (err != 0) { freeaddrinfo(res); closesocket(fd); return -1; }
    nb = 0; ioctlsocket(fd, FIONBIO, &nb);
#else
    if (::connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res); ::close(fd); return -1;
    }
#endif
    freeaddrinfo(res);
    return fd;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// HttpOutbound

HttpOutbound::HttpOutbound(const std::string& proxyAddr, bool https,
                           const std::string& serverName, bool insecureSkipVerify,
                           const std::string& user, const std::string& pass)
    : proxyAddr_(proxyAddr), https_(https),
      serverName_(serverName.empty() ? proxyAddr : serverName),
      insecureSkipVerify_(insecureSkipVerify) {
    if (!user.empty()) {
        basicAuth_ = "Basic " + base64Encode(user + ":" + pass);
    }
}

std::shared_ptr<server::IConn> HttpOutbound::TCP(const std::string& reqAddr) {
    // Connect to proxy
    int fd = dialProxy(proxyAddr_);
    if (fd < 0) {
        throw std::runtime_error("HTTP outbound: failed to connect to proxy " + proxyAddr_);
    }

    // Wrap with TLS if needed
    std::unique_ptr<server::IConn> conn;
    if (https_) {
#if HY2_OPENSSL_AVAILABLE
        conn = std::make_unique<TlsTcpConn>(fd, serverName_, insecureSkipVerify_);
#else
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        throw std::runtime_error("HTTP outbound: TLS not available (OpenSSL not found)");
#endif
    } else {
        conn = std::make_unique<RawTcpConn>(fd);
    }

    // Send CONNECT request
    std::string req = "CONNECT " + reqAddr + " HTTP/1.1\r\n"
                      "Host: " + reqAddr + "\r\n"
                      "Proxy-Connection: Keep-Alive\r\n";
    if (!basicAuth_.empty()) {
        req += "Proxy-Authorization: " + basicAuth_ + "\r\n";
    }
    req += "\r\n";

    conn->Write(reinterpret_cast<const uint8_t*>(req.data()), req.size());

    // Read response status line
    std::string statusLine = readLine(*conn);
    if (statusLine.empty()) {
        conn->Close();
        throw std::runtime_error("HTTP outbound: no response from proxy");
    }

    // Parse status code (e.g., "HTTP/1.1 200 OK")
    int statusCode = 0;
    auto spacePos = statusLine.find(' ');
    if (spacePos != std::string::npos) {
        statusCode = std::atoi(statusLine.c_str() + spacePos + 1);
    }

    // Read remaining headers until empty line
    while (true) {
        std::string line = readLine(*conn);
        if (line.empty()) break;
    }

    if (statusCode != 200) {
        conn->Close();
        throw std::runtime_error("HTTP outbound: CONNECT failed with status " +
                                 std::to_string(statusCode));
    }

    // Release ownership of the connection
    return std::shared_ptr<server::IConn>(conn.release());
}

std::shared_ptr<server::IUdpConn> HttpOutbound::UDP(const std::string& /*reqAddr*/) {
    throw std::runtime_error("UDP not supported by HTTP proxy");
}

bool HttpOutbound::CheckUDP(const std::string& /*reqAddr*/) {
    return false;
}

} // namespace hy2::outbounds
