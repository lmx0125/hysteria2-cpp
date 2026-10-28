#include "hytest.hpp"
#include "hy2/outbounds/dns_outbound.hpp"
#include <future>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

namespace {
struct LocalDnsSocket {
    WSADATA data{};
    SOCKET socket = INVALID_SOCKET;
    sockaddr_in addr{};
    LocalDnsSocket() {
        if (WSAStartup(MAKEWORD(2,2), &data) != 0) throw std::runtime_error("WSAStartup");
        socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (socket == INVALID_SOCKET || ::bind(socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            if (socket != INVALID_SOCKET) closesocket(socket);
            WSACleanup();
            throw std::runtime_error("bind local DNS socket");
        }
        int len = sizeof(addr);
        getsockname(socket, reinterpret_cast<sockaddr*>(&addr), &len);
    }
    ~LocalDnsSocket() { closesocket(socket); WSACleanup(); }
    std::string Address() const { return "127.0.0.1:" + std::to_string(ntohs(addr.sin_port)); }
};
}

HY_TEST(DnsResolver_StandardSilentServerHasReadDeadline) {
    // Keep a real UDP port open without responding. This reproduces the
    // previous indefinite recv() without depending on external DNS access.
    LocalDnsSocket server;
    hy2::outbounds::StandardDnsResolver resolver(server.Address());
    const auto start = std::chrono::steady_clock::now();
    const auto result = resolver.Resolve("example.test");
    const auto elapsed = std::chrono::steady_clock::now() - start;
    HY_CHECK(result.error == "DNS response timeout");
    HY_CHECK(!result.hasIpv4 && !result.hasIpv6);
    HY_CHECK(elapsed >= std::chrono::seconds(2));
    HY_CHECK(elapsed < std::chrono::seconds(5));
}

HY_TEST(DnsResolver_StandardReadyResponseDoesNotWaitForDeadline) {
    LocalDnsSocket server;
    auto responder = std::async(std::launch::async, [&] {
        fd_set fds; FD_ZERO(&fds); FD_SET(server.socket, &fds);
        timeval timeout{3,0};
        if (::select(0, &fds, nullptr, nullptr, &timeout) <= 0) return false;
        char request[1024]; sockaddr_in peer{}; int peerLen = sizeof(peer);
        const int n = recvfrom(server.socket, request, sizeof(request), 0,
                               reinterpret_cast<sockaddr*>(&peer), &peerLen);
        if (n < 12) return false;
        // Echo the first question and append an A answer for 203.0.113.7.
        size_t questionEnd=12;
        while (questionEnd<size_t(n) && request[questionEnd]!=0)
            questionEnd+=1+static_cast<unsigned char>(request[questionEnd]);
        questionEnd+=5;
        if (questionEnd>size_t(n)) return false;
        std::vector<unsigned char> response(request,request+questionEnd);
        response[2]=0x81; response[3]=0x80;
        response[4]=0; response[5]=1; response[6]=0; response[7]=1;
        const unsigned char answer[]={0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,203,0,113,7};
        for (auto b:answer) response.push_back(b);
        return sendto(server.socket, reinterpret_cast<const char*>(response.data()), static_cast<int>(response.size()), 0,
                      reinterpret_cast<sockaddr*>(&peer), peerLen) == static_cast<int>(response.size());
    });
    hy2::outbounds::StandardDnsResolver resolver(server.Address());
    const auto start = std::chrono::steady_clock::now();
    const auto result = resolver.Resolve("example.test");
    const auto elapsed = std::chrono::steady_clock::now() - start;
    HY_CHECK(responder.get());
    HY_CHECK(result.hasIpv4);HY_CHECK(result.ipv4=="203.0.113.7");
    HY_CHECK(elapsed < std::chrono::seconds(1));
}
#endif
