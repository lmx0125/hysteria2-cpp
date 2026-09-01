// direct_outbound_test.cpp - Tests for DirectOutbound (TCP/UDP dial).
// Verifies wire-compatible behavior with Go's ob_direct.go.
#include "hytest.hpp"
#include "hy2/outbounds/direct.hpp"
#include "hy2/server_iface.hpp"

#include <cstring>
#include <thread>
#include <chrono>
#include <atomic>

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

using namespace hy2::outbounds;

// ---------------------------------------------------------------------------
// Helper: minimal TCP echo server for testing

class TcpEchoServer {
public:
    TcpEchoServer() {
#ifdef _WIN32
        WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
#endif
        listenFd_ = static_cast<int>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (listenFd_ < 0) return;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close();
            return;
        }
        socklen_t len = sizeof(addr);
        getsockname(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);

        listen(listenFd_, 1);
        running_ = true;
        thread_ = std::thread([this] { run(); });
    }

    ~TcpEchoServer() { close(); }

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
            struct timeval tv{0, 100000}; // 100ms
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

            // Echo loop
            std::thread([this, clientFd] {
                uint8_t buf[4096];
                for (;;) {
                    int n = static_cast<int>(::recv(clientFd, reinterpret_cast<char*>(buf),
                                                    sizeof(buf), 0));
                    if (n <= 0) break;
                    ::send(clientFd, reinterpret_cast<const char*>(buf), n, 0);
                }
#ifdef _WIN32
                closesocket(clientFd);
#else
                ::close(clientFd);
#endif
            }).detach();
        }
    }

    int listenFd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

// ---------------------------------------------------------------------------
// Helper: minimal UDP echo server for testing

class UdpEchoServer {
public:
    UdpEchoServer() {
        fd_ = static_cast<int>(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        if (fd_ < 0) return;

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            close();
            return;
        }
        socklen_t len = sizeof(addr);
        getsockname(fd_, reinterpret_cast<struct sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);

        running_ = true;
        thread_ = std::thread([this] { run(); });
    }

    ~UdpEchoServer() { close(); }

    uint16_t port() const { return port_; }
    bool ok() const { return running_; }

    void close() {
        running_ = false;
        if (fd_ >= 0) {
#ifdef _WIN32
            closesocket(fd_);
#else
            ::close(fd_);
#endif
            fd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

private:
    void run() {
        uint8_t buf[65536];
        while (running_) {
            struct sockaddr_in from{};
            socklen_t fromlen = sizeof(from);
            int n = ::recvfrom(fd_, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                               reinterpret_cast<struct sockaddr*>(&from), &fromlen);
            if (n <= 0) continue;
            // Echo back
            ::sendto(fd_, reinterpret_cast<const char*>(buf), n, 0,
                     reinterpret_cast<struct sockaddr*>(&from), fromlen);
        }
    }

    int fd_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> running_{false};
    std::thread thread_;
};

// ---------------------------------------------------------------------------
// Tests

HY_TEST(DirectOutbound_TCP_Connect) {
    TcpEchoServer server;
    HY_CHECK(server.ok());

    DirectOutbound ob(DirectOutboundMode::Auto);
    std::string addr = "127.0.0.1:" + std::to_string(server.port());

    auto conn = ob.TCP(addr);
    HY_CHECK(conn != nullptr);

    // Send and receive
    const char* msg = "hello hy2";
    conn->Write(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    uint8_t buf[64] = {};
    size_t n = conn->Read(buf, sizeof(buf));
    HY_CHECK(n > 0);
    HY_CHECK(std::string(reinterpret_cast<char*>(buf), n) == "hello hy2");

    conn->Close();
}

HY_TEST(DirectOutbound_TCP_LargePayload) {
    TcpEchoServer server;
    HY_CHECK(server.ok());

    DirectOutbound ob(DirectOutboundMode::Auto);
    std::string addr = "127.0.0.1:" + std::to_string(server.port());

    auto conn = ob.TCP(addr);
    HY_CHECK(conn != nullptr);

    // 64KB payload
    std::vector<uint8_t> payload(65536);
    for (size_t i = 0; i < payload.size(); i++) {
        payload[i] = static_cast<uint8_t>(i & 0xFF);
    }

    conn->Write(payload.data(), payload.size());

    // Read all back
    std::vector<uint8_t> received;
    uint8_t buf[4096];
    while (received.size() < payload.size()) {
        size_t n = conn->Read(buf, sizeof(buf));
        if (n == 0) break;
        received.insert(received.end(), buf, buf + n);
    }

    HY_CHECK(received.size() == payload.size());
    HY_CHECK(received == payload);

    conn->Close();
}

HY_TEST(DirectOutbound_TCP_ConnectFailure) {
    DirectOutbound ob(DirectOutboundMode::Auto);
    // Port 1 is unlikely to have a listener
    bool threw = false;
    try {
        ob.TCP("127.0.0.1:1");
    } catch (...) {
        threw = true;
    }
    HY_CHECK(threw);
}

HY_TEST(DirectOutbound_TCP_InvalidAddress) {
    DirectOutbound ob(DirectOutboundMode::Auto);
    bool threw = false;
    try {
        ob.TCP("no-colon-address");
    } catch (...) {
        threw = true;
    }
    HY_CHECK(threw);
}

HY_TEST(DirectOutbound_UDP_SendReceive) {
    UdpEchoServer server;
    HY_CHECK(server.ok());

    DirectOutbound ob(DirectOutboundMode::Auto);
    std::string addr = "127.0.0.1:" + std::to_string(server.port());

    auto conn = ob.UDP(addr);
    HY_CHECK(conn != nullptr);

    // Send a datagram
    const char* msg = "udp test";
    conn->WriteTo(reinterpret_cast<const uint8_t*>(msg), strlen(msg), addr);

    // Read echo back
    uint8_t buf[64] = {};
    std::string from;
    size_t n = conn->ReadFrom(buf, sizeof(buf), from);
    HY_CHECK(n > 0);
    HY_CHECK(std::string(reinterpret_cast<char*>(buf), n) == "udp test");

    conn->Close();
}

HY_TEST(DirectOutbound_CheckUDP) {
    DirectOutbound ob(DirectOutboundMode::Auto);
    HY_CHECK(ob.CheckUDP("127.0.0.1:53") == true);
}

HY_TEST(DirectOutbound_ModeSelection) {
    // All modes should at least create without crashing
    DirectOutbound obAuto(DirectOutboundMode::Auto);
    DirectOutbound ob46(DirectOutboundMode::IPv4Prefer);
    DirectOutbound ob64(DirectOutboundMode::IPv6Prefer);
    DirectOutbound ob4(DirectOutboundMode::IPv4Only);
    DirectOutbound ob6(DirectOutboundMode::IPv6Only);

    // IPv4Only should work with 127.0.0.1
    TcpEchoServer server;
    HY_CHECK(server.ok());

    std::string addr = "127.0.0.1:" + std::to_string(server.port());
    auto conn = ob4.TCP(addr);
    HY_CHECK(conn != nullptr);
    conn->Close();
}
