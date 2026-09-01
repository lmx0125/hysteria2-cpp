// linux_tproxy.cpp - Linux TPROXY transparent proxy implementation.
// Uses IP_TRANSPARENT socket option to intercept redirected traffic.

#ifdef __linux__

#include "hy2/platform/linux/linux_tproxy.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>

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
#include <thread>

namespace hy2::platform::linux_impl {

// ---------------------------------------------------------------------------
// LinuxTcpTProxy

LinuxTcpTProxy::LinuxTcpTProxy(TcpDialFunc dialFunc,
                                 std::shared_ptr<ITransparentProxyEventLogger> logger)
    : dialFunc_(std::move(dialFunc)), logger_(std::move(logger)) {}

LinuxTcpTProxy::~LinuxTcpTProxy() {
    Stop();
}

bool LinuxTcpTProxy::Start(const std::string& listenAddr) {
    // Parse address
    auto colon = listenAddr.rfind(':');
    if (colon == std::string::npos) return false;

    std::string host = listenAddr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(listenAddr.c_str() + colon + 1));

    // Create socket
    listenFd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd_ < 0) return false;

    // Set IP_TRANSPARENT to accept connections for any destination
    int opt = 1;
    if (setsockopt(listenFd_, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) < 0) {
        close(listenFd_);
        listenFd_ = -1;
        return false;
    }

    // Allow address reuse
    setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind
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

    // Listen
    if (listen(listenFd_, 128) < 0) {
        close(listenFd_);
        listenFd_ = -1;
        return false;
    }

    running_ = true;
    acceptThread_ = std::thread(&LinuxTcpTProxy::acceptLoop, this, listenFd_);
    return true;
}

void LinuxTcpTProxy::Stop() {
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

void LinuxTcpTProxy::acceptLoop(int listenFd) {
    while (running_) {
        struct sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        int connFd = accept(listenFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
        if (connFd < 0) {
            if (!running_) break;
            continue;
        }

        // In TPROXY mode, LocalAddr() is the original destination
        struct sockaddr_in localAddr{};
        socklen_t localLen = sizeof(localAddr);
        getsockname(connFd, reinterpret_cast<struct sockaddr*>(&localAddr), &localLen);

        char dstIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &localAddr.sin_addr, dstIp, sizeof(dstIp));
        std::string originalDest = std::string(dstIp) + ":" + std::to_string(ntohs(localAddr.sin_port));

        std::thread(&LinuxTcpTProxy::handleConnection, this, connFd, originalDest).detach();
    }
}

void LinuxTcpTProxy::handleConnection(int connFd, const std::string& originalDest) {
    if (logger_) {
        logger_->OnConnect(originalDest, "");
    }

    std::string closeErr;
    auto cleanup = [&]() {
        if (logger_) {
            logger_->OnError(originalDest, "", closeErr);
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

// ---------------------------------------------------------------------------
// LinuxUdpTProxy

LinuxUdpTProxy::LinuxUdpTProxy(UdpDialFunc dialFunc,
                                 std::shared_ptr<ITransparentProxyEventLogger> logger,
                                 uint32_t timeoutMs)
    : dialFunc_(std::move(dialFunc)), logger_(std::move(logger)), timeoutMs_(timeoutMs) {}

LinuxUdpTProxy::~LinuxUdpTProxy() {
    Stop();
}

bool LinuxUdpTProxy::Start(const std::string& listenAddr) {
    auto colon = listenAddr.rfind(':');
    if (colon == std::string::npos) return false;

    std::string host = listenAddr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(listenAddr.c_str() + colon + 1));

    listenFd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenFd_ < 0) return false;

    int opt = 1;
    setsockopt(listenFd_, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
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

    running_ = true;
    receiveThread_ = std::thread(&LinuxUdpTProxy::receiveLoop, this, listenFd_);
    return true;
}

void LinuxUdpTProxy::Stop() {
    running_ = false;
    if (listenFd_ >= 0) {
        shutdown(listenFd_, SHUT_RDWR);
        close(listenFd_);
        listenFd_ = -1;
    }
    if (receiveThread_.joinable()) {
        receiveThread_.join();
    }
}

void LinuxUdpTProxy::receiveLoop(int listenFd) {
    uint8_t buf[4096];
    while (running_) {
        struct sockaddr_in srcAddr{}, dstAddr{};
        socklen_t srcLen = sizeof(srcAddr), dstLen = sizeof(dstAddr);

        // Use recvmsg to get original destination via IP_RECVORIGDSTADDR
        struct iovec iov{};
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);

        struct msghdr msg{};
        msg.msg_name = &srcAddr;
        msg.msg_namelen = srcLen;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        // Control buffer for original destination
        union {
            struct cmsghdr align;
            char control[CMSG_SPACE(sizeof(struct sockaddr_in))];
        } controlBuf{};
        msg.msg_control = controlBuf.control;
        msg.msg_controllen = sizeof(controlBuf.control);

        ssize_t n = recvmsg(listenFd, &msg, 0);
        if (n <= 0) {
            if (!running_) break;
            continue;
        }

        // Extract original destination from control messages
        std::string dstStr;
        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
             cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
                auto* origDst = reinterpret_cast<struct sockaddr_in*>(CMSG_DATA(cmsg));
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &origDst->sin_addr, ip, sizeof(ip));
                dstStr = std::string(ip) + ":" + std::to_string(ntohs(origDst->sin_port));
                break;
            }
        }

        if (dstStr.empty()) continue;

        char srcIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &srcAddr.sin_addr, srcIp, sizeof(srcIp));
        std::string srcStr = std::string(srcIp) + ":" + std::to_string(ntohs(srcAddr.sin_port));

        std::vector<uint8_t> pkt(buf, buf + n);
        std::thread(&LinuxUdpTProxy::handleSession, this, listenFd, srcStr, dstStr, pkt).detach();
    }
}

void LinuxUdpTProxy::handleSession(int listenFd,
                                    const std::string& srcAddr,
                                    const std::string& dstAddr,
                                    const std::vector<uint8_t>& firstPacket) {
    if (logger_) {
        logger_->OnConnect(dstAddr, srcAddr);
    }

    std::string closeErr;
    auto cleanup = [&]() {
        if (logger_) {
            logger_->OnError(dstAddr, srcAddr, closeErr);
        }
    };

    // Create a connected UDP socket that spoofs the source address
    // This allows replies to appear to come from the original destination
    auto connFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (connFd < 0) {
        closeErr = "failed to create UDP socket";
        cleanup();
        return;
    }

    int opt = 1;
    setsockopt(connFd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));

    // Parse addresses
    struct sockaddr_in localAddr{}, remoteAddr{};

    auto colon = dstAddr.rfind(':');
    std::string dstHost = dstAddr.substr(0, colon);
    uint16_t dstPort = static_cast<uint16_t>(std::atoi(dstAddr.c_str() + colon + 1));
    localAddr.sin_family = AF_INET;
    inet_pton(AF_INET, dstHost.c_str(), &localAddr.sin_addr);
    localAddr.sin_port = htons(dstPort);

    colon = srcAddr.rfind(':');
    std::string srcHost = srcAddr.substr(0, colon);
    uint16_t srcPort = static_cast<uint16_t>(std::atoi(srcAddr.c_str() + colon + 1));
    remoteAddr.sin_family = AF_INET;
    inet_pton(AF_INET, srcHost.c_str(), &remoteAddr.sin_addr);
    remoteAddr.sin_port = htons(srcPort);

    // Bind to original destination address (spoofing)
    if (bind(connFd, reinterpret_cast<struct sockaddr*>(&localAddr), sizeof(localAddr)) < 0) {
        closeErr = "failed to bind spoofed address";
        close(connFd);
        cleanup();
        return;
    }

    // Connect back to client
    connect(connFd, reinterpret_cast<struct sockaddr*>(&remoteAddr), sizeof(remoteAddr));

    // Open Hysteria2 UDP session
    auto hyConn = dialFunc_();
    if (!hyConn) {
        closeErr = "failed to open UDP session";
        close(connFd);
        cleanup();
        return;
    }

    // Send first packet
    hyConn->Send(firstPacket.data(), firstPacket.size(), dstAddr);

    // Bidirectional forwarding
    std::atomic<bool> done{false};
    auto forwarding = [&]() {
        uint8_t buf[4096];
        while (!done) {
            struct pollfd pfd{};
            pfd.fd = connFd;
            pfd.events = POLLIN;
            int ret = poll(&pfd, 1, timeoutMs_ > 0 ? timeoutMs_ : 60000);
            if (ret <= 0) break;

            ssize_t n = read(connFd, buf, sizeof(buf));
            if (n <= 0) break;

            hyConn->Send(buf, n, dstAddr);
        }
        bool expected = false;
        done.compare_exchange_strong(expected, true);
    };

    auto remoteToLocal = [&]() {
        std::vector<uint8_t> data;
        std::string addr;
        while (!done) {
            if (!hyConn->Receive(data, addr)) break;
            send(connFd, data.data(), data.size(), 0);
        }
        bool expected = false;
        done.compare_exchange_strong(expected, true);
    };

    std::thread t1(forwarding);
    std::thread t2(remoteToLocal);
    t1.join();
    t2.join();

    hyConn->Close();
    close(connFd);
    cleanup();
}

} // namespace hy2::platform::linux_impl

#endif // __linux__
