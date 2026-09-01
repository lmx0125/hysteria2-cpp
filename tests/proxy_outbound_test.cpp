// proxy_outbound_test.cpp - Tests for HTTP CONNECT and SOCKS5 outbounds.
#include "hytest.hpp"
#include "hy2/outbounds/http_outbound.hpp"
#include "hy2/outbounds/socks5_outbound.hpp"

#include <thread>
#include <atomic>
#include <cstring>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
#endif

// ---------------------------------------------------------------------------
// Minimal mock HTTP CONNECT proxy server

class MockHttpProxy {
public:
    MockHttpProxy() {
        listenFd_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (listenFd_ < 0) return;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(); return;
        }
        socklen_t len = sizeof(addr);
        getsockname(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);

        listen(listenFd_, 1);
        running_ = true;
        thread_ = std::thread([this] { run(); });
    }

    ~MockHttpProxy() { close(); }

    uint16_t port() const { return port_; }
    bool ok() const { return running_; }
    std::string lastTarget() const { return lastTarget_; }

    void close() {
        running_ = false;
        if (listenFd_ >= 0) {
#ifdef _WIN32
            closesocket(listenFd_);
#else
            ::close(listenFd_);
#endif
            listenFd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
#ifdef _WIN32
            FD_SET(static_cast<SOCKET>(listenFd_), &rfds);
#else
            FD_SET(listenFd_, &rfds);
#endif
            struct timeval tv{0, 100000};
#ifdef _WIN32
            if (select(0, &rfds, nullptr, nullptr, &tv) <= 0) continue;
#else
            if (select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv) <= 0) continue;
#endif

            struct sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            int clientFd = static_cast<int>(accept(listenFd_,
                reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen));
            if (clientFd < 0) continue;

            std::thread([this, clientFd] {
                handleClient(clientFd);
            }).detach();
        }
    }

    void handleClient(int fd) {
        // Read request line
        std::string request;
        char c;
        while (::recv(fd, &c, 1, 0) == 1 && c != '\n') {
            if (c != '\r') request.push_back(c);
        }

        // Parse "CONNECT host:port HTTP/1.1"
        auto space1 = request.find(' ');
        auto space2 = request.find(' ', space1 + 1);
        if (space1 != std::string::npos && space2 != std::string::npos) {
            lastTarget_ = request.substr(space1 + 1, space2 - space1 - 1);
        }

        // Read remaining headers
        std::string line;
        while (::recv(fd, &c, 1, 0) == 1) {
            if (c == '\n') {
                if (line.empty()) break; // empty line = end of headers
                line.clear();
            } else if (c != '\r') {
                line.push_back(c);
            }
        }

        // Send 200 OK
        const char* resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
        ::send(fd, resp, static_cast<int>(strlen(resp)), 0);

        // Echo back any data (for testing)
        char buf[4096];
        for (;;) {
            int n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            ::send(fd, buf, n, 0);
        }
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
    }

    int listenFd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::string lastTarget_;
};

// ---------------------------------------------------------------------------
// Minimal mock SOCKS5 server

class MockSocks5 {
public:
    MockSocks5() {
        listenFd_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (listenFd_ < 0) return;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close(); return;
        }
        socklen_t len = sizeof(addr);
        getsockname(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);

        listen(listenFd_, 1);
        running_ = true;
        thread_ = std::thread([this] { run(); });
    }

    ~MockSocks5() { close(); }

    uint16_t port() const { return port_; }
    bool ok() const { return running_; }

    void close() {
        running_ = false;
        if (listenFd_ >= 0) {
#ifdef _WIN32
            closesocket(listenFd_);
#else
            ::close(listenFd_);
#endif
            listenFd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
#ifdef _WIN32
            FD_SET(static_cast<SOCKET>(listenFd_), &rfds);
#else
            FD_SET(listenFd_, &rfds);
#endif
            struct timeval tv{0, 100000};
#ifdef _WIN32
            if (select(0, &rfds, nullptr, nullptr, &tv) <= 0) continue;
#else
            if (select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv) <= 0) continue;
#endif

            struct sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            int clientFd = static_cast<int>(accept(listenFd_,
                reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen));
            if (clientFd < 0) continue;

            std::thread([this, clientFd] {
                handleClient(clientFd);
            }).detach();
        }
    }

    void handleClient(int fd) {
        // Read negotiation request
        uint8_t buf[4];
        if (::recv(fd, reinterpret_cast<char*>(buf), 2, 0) != 2) {
#ifdef _WIN32
            closesocket(fd);
#else
            ::close(fd);
#endif
            return;
        }
        uint8_t nMethods = buf[1];
        // Skip methods
        uint8_t methods[256];
        if (::recv(fd, reinterpret_cast<char*>(methods), nMethods, 0) != nMethods) {
#ifdef _WIN32
            closesocket(fd);
#else
            ::close(fd);
#endif
            return;
        }

        // Reply: no auth required
        uint8_t negResp[2] = {0x05, 0x00};
        ::send(fd, reinterpret_cast<const char*>(negResp), 2, 0);

        // Read CONNECT request
        uint8_t req[256];
        if (::recv(fd, reinterpret_cast<char*>(req), 4, 0) != 4) {
#ifdef _WIN32
            closesocket(fd);
#else
            ::close(fd);
#endif
            return;
        }
        uint8_t atyp = req[3];
        size_t addrLen = 0;
        if (atyp == 0x01) addrLen = 4;
        else if (atyp == 0x03) {
            uint8_t dlen;
            ::recv(fd, reinterpret_cast<char*>(&dlen), 1, 0);
            req[4] = dlen;
            addrLen = dlen;
        } else if (atyp == 0x04) addrLen = 16;

        if (addrLen > 0) {
            ::recv(fd, reinterpret_cast<char*>(req + 4), static_cast<int>(addrLen + 2), 0);
        }

        // Reply: success (IPv4 0.0.0.0:0)
        uint8_t reply[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        ::send(fd, reinterpret_cast<const char*>(reply), 10, 0);

        // Echo back
        char echoBuf[4096];
        for (;;) {
            int n = ::recv(fd, echoBuf, sizeof(echoBuf), 0);
            if (n <= 0) break;
            ::send(fd, echoBuf, n, 0);
        }
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
    }

    int listenFd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

// ---------------------------------------------------------------------------
// Tests

HY_TEST(HttpOutbound_BasicConnect) {
    MockHttpProxy proxy;
    HY_CHECK(proxy.ok());

    std::string proxyAddr = "127.0.0.1:" + std::to_string(proxy.port());
    hy2::outbounds::HttpOutbound ob(proxyAddr);

    auto conn = ob.TCP("example.com:443");
    HY_CHECK(conn != nullptr);

    // Send data through the tunnel
    const char* msg = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    conn->Write(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    // Read echo back from mock proxy
    uint8_t buf[4096] = {};
    size_t n = conn->Read(buf, sizeof(buf));
    HY_CHECK(n > 0);

    conn->Close();
}

HY_TEST(HttpOutbound_CheckUDP) {
    hy2::outbounds::HttpOutbound ob("127.0.0.1:8080");
    HY_CHECK(ob.CheckUDP("example.com:443") == false);
}

HY_TEST(HttpOutbound_UDPThrows) {
    hy2::outbounds::HttpOutbound ob("127.0.0.1:8080");
    bool threw = false;
    try {
        ob.UDP("example.com:443");
    } catch (...) {
        threw = true;
    }
    HY_CHECK(threw);
}

HY_TEST(Socks5Outbound_BasicConnect) {
    MockSocks5 proxy;
    HY_CHECK(proxy.ok());

    std::string proxyAddr = "127.0.0.1:" + std::to_string(proxy.port());
    hy2::outbounds::Socks5Outbound ob(proxyAddr);

    auto conn = ob.TCP("example.com:443");
    HY_CHECK(conn != nullptr);

    // Send data
    const char* msg = "hello socks5";
    conn->Write(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    // Read echo back
    uint8_t buf[64] = {};
    size_t n = conn->Read(buf, sizeof(buf));
    HY_CHECK(n > 0);
    HY_CHECK(std::string(reinterpret_cast<char*>(buf), n) == "hello socks5");

    conn->Close();
}

HY_TEST(Socks5Outbound_CheckUDP) {
    hy2::outbounds::Socks5Outbound ob("127.0.0.1:1080");
    HY_CHECK(ob.CheckUDP("example.com:443") == true);
}
