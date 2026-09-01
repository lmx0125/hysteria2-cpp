// socks5_outbound.cpp - SOCKS5 outbound proxy.
// Rewrite of extras/outbounds/ob_socks5.go.
#include "hy2/outbounds/socks5_outbound.hpp"

#include <cstring>
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

namespace hy2::outbounds {

namespace {

constexpr int kNegotiationTimeoutSec = 10;
constexpr int kRequestTimeoutSec = 10;

// SOCKS5 constants
constexpr uint8_t kSocks5Version = 0x05;
constexpr uint8_t kMethodNone = 0x00;
constexpr uint8_t kMethodUsernamePassword = 0x02;
constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kCmdUDPAssociate = 0x03;
constexpr uint8_t kAtypIPv4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypIPv6 = 0x04;
constexpr uint8_t kRepSuccess = 0x00;

// TCP connection wrapper
class TcpConn : public server::IConn {
public:
    explicit TcpConn(int fd) : fd_(fd) {}
    ~TcpConn() override { Close(); }

    size_t Read(uint8_t* p, size_t n) override {
        if (fd_ < 0) return 0;
        int r = static_cast<int>(::recv(fd_, reinterpret_cast<char*>(p),
                                        static_cast<int>(n), 0));
        return r <= 0 ? 0 : static_cast<size_t>(r);
    }

    void Write(const uint8_t* p, size_t n) override {
        if (fd_ < 0) throw std::runtime_error("socks5: conn closed");
        size_t off = 0;
        while (off < n) {
            int w = static_cast<int>(::send(fd_,
                                            reinterpret_cast<const char*>(p + off),
                                            static_cast<int>(n - off), 0));
            if (w <= 0) throw std::runtime_error("socks5: send failed");
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

// Read exactly n bytes
void readExact(server::IConn& conn, uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        size_t r = conn.Read(buf + got, n - got);
        if (r == 0) throw std::runtime_error("socks5: connection closed");
        got += r;
    }
}

// Connect to SOCKS5 proxy
int dialSocks5(const std::string& addr) {
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
    struct timeval tv{kNegotiationTimeoutSec, 0};
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

// Parse SOCKS5 address from reply
std::string parseSocks5Address(const uint8_t* data, size_t len) {
    if (len < 4) return "";
    uint8_t atyp = data[3];
    size_t offset = 4;
    std::string host;

    if (atyp == kAtypIPv4) {
        if (len < 10) return "";
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, data + offset, ip, sizeof(ip));
        host = ip;
        offset += 4;
    } else if (atyp == kAtypDomain) {
        uint8_t dlen = data[offset];
        offset++;
        if (offset + dlen + 2 > len) return "";
        host = std::string(reinterpret_cast<const char*>(data + offset), dlen);
        offset += dlen;
    } else if (atyp == kAtypIPv6) {
        if (len < 22) return "";
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, data + offset, ip, sizeof(ip));
        host = ip;
        offset += 16;
    } else {
        return "";
    }

    uint16_t port = 0;
    if (offset + 2 <= len) {
        port = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    }
    return host + ":" + std::to_string(port);
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Socks5Outbound

Socks5Outbound::Socks5Outbound(const std::string& addr,
                               const std::string& username,
                               const std::string& password)
    : addr_(addr), username_(username), password_(password) {}

std::shared_ptr<server::IConn> Socks5Outbound::dialAndNegotiate() {
    int fd = dialSocks5(addr_);
    if (fd < 0) {
        throw std::runtime_error("SOCKS5: failed to connect to " + addr_);
    }
    auto conn = std::make_shared<TcpConn>(fd);

    // Send negotiation request
    std::vector<uint8_t> negReq;
    negReq.push_back(kSocks5Version);
    negReq.push_back(static_cast<uint8_t>(username_.empty() ? 1 : 2)); // nMethods
    negReq.push_back(kMethodNone);
    if (!username_.empty()) {
        negReq.push_back(kMethodUsernamePassword);
    }
    conn->Write(negReq.data(), negReq.size());

    // Read negotiation reply
    uint8_t negResp[2];
    readExact(*conn, negResp, 2);
    if (negResp[0] != kSocks5Version) {
        conn->Close();
        throw std::runtime_error("SOCKS5: invalid version in negotiation reply");
    }
    if (negResp[1] == kMethodUsernamePassword) {
        // Username/Password auth
        std::vector<uint8_t> authReq;
        authReq.push_back(0x01); // version
        authReq.push_back(static_cast<uint8_t>(username_.size()));
        authReq.insert(authReq.end(), username_.begin(), username_.end());
        authReq.push_back(static_cast<uint8_t>(password_.size()));
        authReq.insert(authReq.end(), password_.begin(), password_.end());
        conn->Write(authReq.data(), authReq.size());

        uint8_t authResp[2];
        readExact(*conn, authResp, 2);
        if (authResp[1] != 0x00) {
            conn->Close();
            throw std::runtime_error("SOCKS5: authentication failed");
        }
    } else if (negResp[1] != kMethodNone) {
        conn->Close();
        throw std::runtime_error("SOCKS5: unsupported auth method");
    }

    return conn;
}

std::string Socks5Outbound::sendRequest(server::IConn& conn, uint8_t cmd,
                                        const std::string& targetAddr) {
    // Parse target address
    auto colon = targetAddr.rfind(':');
    std::string host = (colon != std::string::npos) ? targetAddr.substr(0, colon) : "";
    uint16_t port = (colon != std::string::npos)
        ? static_cast<uint16_t>(std::atoi(targetAddr.c_str() + colon + 1))
        : 0;

    // Build SOCKS5 request
    std::vector<uint8_t> req;
    req.push_back(kSocks5Version);
    req.push_back(cmd);
    req.push_back(0x00); // reserved

    // Try to parse as IP
    struct in_addr addr4{};
    struct in6_addr addr6{};
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) {
        req.push_back(kAtypIPv4);
        auto* p = reinterpret_cast<uint8_t*>(&addr4);
        req.insert(req.end(), p, p + 4);
    } else if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1) {
        req.push_back(kAtypIPv6);
        auto* p = reinterpret_cast<uint8_t*>(&addr6);
        req.insert(req.end(), p, p + 16);
    } else {
        req.push_back(kAtypDomain);
        req.push_back(static_cast<uint8_t>(host.size()));
        req.insert(req.end(), host.begin(), host.end());
    }

    req.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    req.push_back(static_cast<uint8_t>(port & 0xFF));

    conn.Write(req.data(), req.size());

    // Read reply (at least 10 bytes for IPv4)
    uint8_t reply[22]; // max for IPv6
    readExact(conn, reply, 4); // ver, rep, rsv, atyp

    size_t extraLen = 0;
    if (reply[3] == kAtypIPv4) extraLen = 6; // 4 + 2
    else if (reply[3] == kAtypDomain) {
        uint8_t dlen = 0;
        readExact(conn, &dlen, 1);
        extraLen = dlen + 2;
    } else if (reply[3] == kAtypIPv6) extraLen = 18; // 16 + 2

    if (extraLen > 0) {
        readExact(conn, reply + 4, extraLen);
    }

    if (reply[1] != kRepSuccess) {
        conn.Close();
        std::string msg;
        switch (reply[1]) {
        case 0x01: msg = "general failure"; break;
        case 0x02: msg = "connection not allowed"; break;
        case 0x03: msg = "network unreachable"; break;
        case 0x04: msg = "host unreachable"; break;
        case 0x05: msg = "connection refused"; break;
        case 0x06: msg = "TTL expired"; break;
        case 0x07: msg = "command not supported"; break;
        case 0x08: msg = "address type not supported"; break;
        default: msg = "unknown error"; break;
        }
        throw std::runtime_error("SOCKS5 request failed: " + msg);
    }

    // Parse bind address from reply
    return parseSocks5Address(reply, 4 + extraLen);
}

std::shared_ptr<server::IConn> Socks5Outbound::TCP(const std::string& reqAddr) {
    auto conn = dialAndNegotiate();
    sendRequest(*conn, kCmdConnect, reqAddr);
    return conn;
}

std::shared_ptr<server::IUdpConn> Socks5Outbound::UDP(const std::string& /*reqAddr*/) {
    // Full UDP ASSOCIATE implementation would be complex.
    // For now, throw to indicate not supported at this level.
    throw std::runtime_error("SOCKS5 UDP ASSOCIATE not yet implemented");
}

bool Socks5Outbound::CheckUDP(const std::string& /*reqAddr*/) {
    return true; // SOCKS5 supports UDP ASSOCIATE
}

} // namespace hy2::outbounds
