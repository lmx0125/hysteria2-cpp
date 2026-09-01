// linux_redirector.cpp - Linux REDIRECT transparent proxy implementation.

#ifdef __linux__

#include "hy2/platform/linux/linux_redirector.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>
#include <thread>

// HybridByteReaderWriter wraps a socket fd as IByteReaderWriter.
class HybridByteReaderWriter : public hy2::IByteReaderWriter {
public:
    explicit HybridByteReaderWriter(int fd) : fd_(fd) {}
    size_t Read(uint8_t* p, size_t n) override {
        if (fd_ < 0) return 0;
        ssize_t r = ::recv(fd_, p, n, 0);
        return r <= 0 ? 0 : static_cast<size_t>(r);
    }
    void Write(const uint8_t* p, size_t n) override {
        if (fd_ < 0) return;
        size_t off = 0;
        while (off < n) {
            ssize_t w = ::send(fd_, p + off, n - off, 0);
            if (w <= 0) return;
            off += static_cast<size_t>(w);
        }
    }
    void Close() override { fd_ = -1; }
private:
    int fd_;
};

namespace hy2::platform::linux_impl {

// SO_ORIGINAL_DST and SO_ORIGINAL_DSTV6 are both 80 on Linux
constexpr int SO_ORIGINAL_DST = 80;
constexpr int SO_ORIGINAL_DSTV6 = 80;

LinuxTcpRedirector::LinuxTcpRedirector(TcpDialFunc dialFunc,
                                        std::shared_ptr<IRedirectorEventLogger> logger)
    : dialFunc_(std::move(dialFunc)), logger_(std::move(logger)) {}

LinuxTcpRedirector::~LinuxTcpRedirector() {
    Stop();
}

bool LinuxTcpRedirector::Start(const std::string& listenAddr) {
    auto colon = listenAddr.rfind(':');
    if (colon == std::string::npos) return false;

    std::string host = listenAddr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(listenAddr.c_str() + colon + 1));

    listenFd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd_ < 0) return false;

    int opt = 1;
    setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host.empty() || host == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    }

    if (bind(listenFd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(listenFd_);
        listenFd_ = -1;
        return false;
    }

    if (listen(listenFd_, 128) < 0) {
        close(listenFd_);
        listenFd_ = -1;
        return false;
    }

    running_ = true;
    acceptThread_ = std::thread(&LinuxTcpRedirector::acceptLoop, this, listenFd_);
    return true;
}

void LinuxTcpRedirector::Stop() {
    running_ = false;
    if (listenFd_ >= 0) {
        shutdown(listenFd_, SHUT_RDWR);
        close(listenFd_);
        listenFd_ = -1;
    }
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
}

void LinuxTcpRedirector::acceptLoop(int listenFd) {
    while (running_) {
        struct sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int connFd = accept(listenFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
        if (connFd < 0) {
            if (!running_) break;
            continue;
        }

        std::thread(&LinuxTcpRedirector::handleConnection, this, connFd).detach();
    }
}

std::string LinuxTcpRedirector::getOriginalDest(int fd) {
    // Try IPv6 first
    struct sockaddr_in6 addr6{};
    socklen_t len6 = sizeof(addr6);
    if (getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DSTV6, &addr6, &len6) == 0) {
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr6.sin6_addr, ip, sizeof(ip));
        return std::string("[") + ip + "]:" + std::to_string(ntohs(addr6.sin6_port));
    }

    // Try IPv4
    struct sockaddr_in addr4{};
    socklen_t len4 = sizeof(addr4);
    if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &addr4, &len4) == 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr4.sin_addr, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(addr4.sin_port));
    }

    return "";
}

void LinuxTcpRedirector::handleConnection(int connFd) {
    // Get original destination
    std::string originalDest = getOriginalDest(connFd);
    if (originalDest.empty()) {
        close(connFd);
        return;
    }

    // Get client address
    struct sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    getpeername(connFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
    char clientIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
    std::string clientStr = std::string(clientIp) + ":" + std::to_string(ntohs(clientAddr.sin_port));

    if (logger_) {
        logger_->OnConnect(clientStr, originalDest);
    }

    std::string closeErr;
    auto cleanup = [&]() {
        if (logger_) {
            logger_->OnError(clientStr, originalDest, closeErr);
        }
    };

    // Open proxied connection to original destination
    auto stream = dialFunc_(originalDest);
    if (!stream) {
        closeErr = "failed to dial " + originalDest;
        close(connFd);
        cleanup();
        return;
    }

    // Bidirectional copy
    std::atomic<bool> done{false};
    auto copier = [&](std::shared_ptr<IByteReaderWriter> src,
                      std::shared_ptr<IByteReaderWriter> dst) {
        uint8_t buf[8192];
        while (true) {
            auto n = src->Read(buf, sizeof(buf));
            if (n <= 0) break;
            dst->Write(buf, n);
        }
        bool expected = false;
        if (done.compare_exchange_strong(expected, true)) {
            shutdown(connFd, SHUT_RDWR);
        }
    };

    auto connStream = std::make_shared<HybridByteReaderWriter>(connFd);
    std::thread t1(copier, connStream, stream);
    std::thread t2(copier, stream, connStream);
    t1.join();
    t2.join();
    close(connFd);
    cleanup();
}

} // namespace hy2::platform::linux_impl

#endif // __linux__
