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

// The UDP send path used to call getaddrinfo() on every datagram (allocating an
// addrinfo list each time, and doing a blocking DNS lookup per packet for a
// hostname target). A session target is constant, so it must be resolved once
// and then cached. This checks both halves: the datagrams still all arrive, and
// the resolve count does not grow with the datagram count.
HY_TEST(DirectOutbound_UdpResolvesTargetOnce) {
    UdpEchoServer server;
    HY_CHECK(server.ok());

    DirectOutbound ob(DirectOutboundMode::IPv4Only);
    const std::string addr = "127.0.0.1:" + std::to_string(server.port());
    auto conn = ob.UDP(addr);
    HY_CHECK(conn != nullptr);

    constexpr size_t kDatagrams = 32;
    const char* msg = "burst";
    const size_t msgLen = std::strlen(msg);

    const uint64_t before = DirectOutboundUdpResolveCount();
    for (size_t i = 0; i < kDatagrams; ++i) {
        conn->WriteTo(reinterpret_cast<const uint8_t*>(msg), msgLen, addr);
    }

    size_t received = 0;
    for (size_t i = 0; i < kDatagrams; ++i) {
        uint8_t buf[64] = {};
        std::string from;
        const size_t n = conn->ReadFrom(buf, sizeof(buf), from);
        if (n == 0) break;
        HY_CHECK(std::string(reinterpret_cast<const char*>(buf), n) == "burst");
        ++received;
    }
    HY_CHECK_EQ(received, kDatagrams);

    const uint64_t after = DirectOutboundUdpResolveCount();
    HY_CHECK(after - before <= 1);

    conn->Close();
}

// Changing the destination must actually change where the datagram goes, i.e.
// the cache must not serve a stale entry for a different address. Each echo
// server replies from its own address, so the reply's source port proves which
// one received the datagram.
HY_TEST(DirectOutbound_UdpTargetChangeFollowed) {
    UdpEchoServer serverA;
    UdpEchoServer serverB;
    HY_CHECK(serverA.ok());
    HY_CHECK(serverB.ok());
    HY_CHECK(serverA.port() != serverB.port());

    DirectOutbound ob(DirectOutboundMode::IPv4Only);
    const std::string addrA = "127.0.0.1:" + std::to_string(serverA.port());
    const std::string addrB = "127.0.0.1:" + std::to_string(serverB.port());
    auto conn = ob.UDP(addrA);
    HY_CHECK(conn != nullptr);

    uint8_t buf[64] = {};
    std::string from;

    const char* toA = "to-A";
    conn->WriteTo(reinterpret_cast<const uint8_t*>(toA), std::strlen(toA), addrA);
    HY_CHECK(conn->ReadFrom(buf, sizeof(buf), from) > 0);
    HY_CHECK_EQ(from, addrA);

    const char* toB = "to-B";
    conn->WriteTo(reinterpret_cast<const uint8_t*>(toB), std::strlen(toB), addrB);
    HY_CHECK(conn->ReadFrom(buf, sizeof(buf), from) > 0);
    HY_CHECK_EQ(from, addrB);

    conn->Close();
}

// ---------------------------------------------------------------------------
// TCP-side hostname caching.
//
// Every proxied TCP connection dials a fresh destination, and "localhost" is a
// real hostname (not a numeric literal), so it went through getaddrinfo() on
// every single dial - blocking the relay worker thread. These pin the cache
// that fixes it.
// ---------------------------------------------------------------------------
HY_TEST(DirectOutbound_TcpResolvesHostnameOnce) {
    TcpEchoServer server;
    HY_CHECK(server.ok());

    DirectOutboundResetTcpResolveCache();
    DirectOutbound ob(DirectOutboundMode::IPv4Only);
    const std::string addr = "localhost:" + std::to_string(server.port());

    // First dial resolves; the rest must be served from the cache.
    for (int i = 0; i < 8; ++i) {
        auto conn = ob.TCP(addr);
        HY_CHECK(conn != nullptr);
        conn->Close();
    }

    HY_CHECK_EQ(DirectOutboundTcpResolveCount(), (uint64_t)1);
}

// A numeric literal must never reach the resolver at all.
HY_TEST(DirectOutbound_TcpNumericLiteralSkipsResolver) {
    TcpEchoServer server;
    HY_CHECK(server.ok());

    DirectOutboundResetTcpResolveCache();
    DirectOutbound ob(DirectOutboundMode::IPv4Only);

    for (int i = 0; i < 4; ++i) {
        auto conn = ob.TCP("127.0.0.1:" + std::to_string(server.port()));
        HY_CHECK(conn != nullptr);
        conn->Close();
    }
    HY_CHECK_EQ(DirectOutboundTcpResolveCount(), (uint64_t)0);
}

// The cache must key on host:port, so a different port is a different target
// and must not be served a stale entry.
HY_TEST(DirectOutbound_TcpCacheKeyedByPort) {
    TcpEchoServer serverA;
    TcpEchoServer serverB;
    HY_CHECK(serverA.ok());
    HY_CHECK(serverB.ok());
    HY_CHECK(serverA.port() != serverB.port());

    DirectOutboundResetTcpResolveCache();
    DirectOutbound ob(DirectOutboundMode::IPv4Only);

    auto a = ob.TCP("localhost:" + std::to_string(serverA.port()));
    auto b = ob.TCP("localhost:" + std::to_string(serverB.port()));
    HY_CHECK(a != nullptr);
    HY_CHECK(b != nullptr);

    // Each distinct host:port resolves once - the second is not a cache hit.
    HY_CHECK_EQ(DirectOutboundTcpResolveCount(), (uint64_t)2);

    // Both still work, i.e. the cache did not cross-wire the two servers.
    for (auto& c : {a, b}) {
        const char* msg = "ping";
        c->Write(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg));
        uint8_t buf[64] = {};
        size_t n = c->Read(buf, sizeof(buf));
        HY_CHECK_EQ(std::string(reinterpret_cast<char*>(buf), n), std::string("ping"));
        c->Close();
    }
}
