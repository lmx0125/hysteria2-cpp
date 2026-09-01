#include "hy2/quic_backend/udp_socket.hpp"

#include <cstring>
#include <algorithm>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>
#endif

namespace hy2::quic_backend {

#ifdef _WIN32
static bool InitWinsock() {
    static bool initialized = false;
    if (!initialized) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
        initialized = true;
    }
    return true;
}
#endif

static int CreateNonBlockingSocket(int af) {
#ifdef _WIN32
    if (!InitWinsock()) return -1;
    SOCKET s = WSASocketW(af, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                          WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) return -1;
    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);
    return static_cast<int>(s);
#else
    int s = socket(af, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return s;
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
    return s;
#endif
}

static bool ResolveAddress(const std::string& host, uint16_t port,
                           struct sockaddr_storage* addr, socklen_t* addrlen) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;

    std::string portStr = std::to_string(port);
    struct addrinfo* result = nullptr;
    int rv = getaddrinfo(host.empty() ? nullptr : host.c_str(),
                         portStr.c_str(), &hints, &result);
    if (rv != 0 || !result) return false;

    // Prefer IPv4 results so a literal "127.0.0.1" bind is never shadowed
    // by a v6-mapped entry on Windows (V6ONLY semantics differ per socket
    // creation flags).
    struct addrinfo* pick = result;
    for (struct addrinfo* ai = result; ai; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) { pick = ai; break; }
    }

    memcpy(addr, pick->ai_addr, pick->ai_addrlen);
    *addrlen = static_cast<socklen_t>(pick->ai_addrlen);
    freeaddrinfo(result);
    return true;
}

// ---------------------------------------------------------------------------
// UdpSocket
// ---------------------------------------------------------------------------

UdpSocket::UdpSocket() = default;

UdpSocket::~UdpSocket() {
    Close();
}

UdpSocket::UdpSocket(UdpSocket&& o) noexcept : fd_(o.fd_), maxDatagramSize_(o.maxDatagramSize_) {
    o.fd_ = -1;
}

UdpSocket& UdpSocket::operator=(UdpSocket&& o) noexcept {
    if (this != &o) {
        Close();
        fd_ = o.fd_;
        maxDatagramSize_ = o.maxDatagramSize_;
        o.fd_ = -1;
    }
    return *this;
}

bool UdpSocket::Bind(const std::string& addr, uint16_t port) {
#ifdef _WIN32
    if (!InitWinsock()) return false;
#endif
    struct sockaddr_storage bindAddr;
    socklen_t bindLen;
    if (!ResolveAddress(addr, port, &bindAddr, &bindLen)) return false;

    fd_ = CreateNonBlockingSocket(bindAddr.ss_family);
    if (fd_ < 0) return false;

    int reuse = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    // Generous receive buffer: the listener drains in a tight loop but
    // bursts from many clients can otherwise overflow and lose packets.
    // 32MB: loopback needs headroom for sender bursts; the default 4MB
    // overflowed when the sender ramped up cwnd during slow start.
    int bufSize = 32 * 1024 * 1024;
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));
    setsockopt(fd_, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));

    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&bindAddr), bindLen) < 0) {
        Close();
        return false;
    }
    return true;
}

bool UdpSocket::Connect(const std::string& addr, uint16_t port) {
#ifdef _WIN32
    if (!InitWinsock()) return false;
#endif
    struct sockaddr_storage remoteAddr;
    socklen_t remoteLen;
    if (!ResolveAddress(addr, port, &remoteAddr, &remoteLen)) return false;

    fd_ = CreateNonBlockingSocket(remoteAddr.ss_family);
    if (fd_ < 0) return false;

    // Generous buffers for bulk transfers on high-BDP or loopback paths.
    int bufSize = 32 * 1024 * 1024;
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));
    setsockopt(fd_, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));

    if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&remoteAddr), remoteLen) < 0) {
        Close();
        return false;
    }
    return true;
}

int UdpSocket::Send(const uint8_t* data, size_t len) {
    if (fd_ < 0) return -1;
#ifdef _WIN32
    int n = send(fd_, reinterpret_cast<const char*>(data),
                 static_cast<int>(len), 0);
    if (n >= 0) { stats_.txSendSuccess++; return n; }
    int werr = WSAGetLastError();
    // WOULDBLOCK: queue the packet
    if (werr == WSAEWOULDBLOCK && txQueue_.size() < kMaxTxQueue) {
        TxPacket pkt;
        pkt.data.assign(data, data + len);
        pkt.hasDest = false;
        txQueue_.push_back(std::move(pkt));
        stats_.txQueueCount++;
        if (txQueue_.size() > stats_.txQueuePeak) stats_.txQueuePeak = txQueue_.size();
        return static_cast<int>(len); // report success to caller
    }
    if (werr == WSAEWOULDBLOCK) stats_.txQueueDrop++;
    if (std::getenv("HY2_BW_DIAG")) {
        std::fprintf(stderr, "[UDP-SEND] error=%d\n", werr);
    }
    return -1;
#else
    ssize_t n = ::send(fd_, data, len, MSG_DONTWAIT);
    if (n >= 0) { stats_.txSendSuccess++; return static_cast<int>(n); }
    // WOULDBLOCK: queue the packet
    if ((errno == EAGAIN || errno == EWOULDBLOCK) && txQueue_.size() < kMaxTxQueue) {
        TxPacket pkt;
        pkt.data.assign(data, data + len);
        pkt.hasDest = false;
        txQueue_.push_back(std::move(pkt));
        stats_.txQueueCount++;
        if (txQueue_.size() > stats_.txQueuePeak) stats_.txQueuePeak = txQueue_.size();
        return static_cast<int>(len); // report success to caller
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) stats_.txQueueDrop++;
    if (errno == EINTR) {
        n = ::send(fd_, data, len, MSG_DONTWAIT);
        return n >= 0 ? static_cast<int>(n) : -1;
    }
    return -1;
#endif
}

int UdpSocket::SendTo(const uint8_t* data, size_t len,
                       const struct sockaddr* to, socklen_t tolen) {
    if (fd_ < 0) return -1;
#ifdef _WIN32
    int n = sendto(fd_, reinterpret_cast<const char*>(data),
                   static_cast<int>(len), 0, to, tolen);
    if (n >= 0) { stats_.txSendSuccess++; return n; }
    // WOULDBLOCK: queue the packet
    if (WSAGetLastError() == WSAEWOULDBLOCK && txQueue_.size() < kMaxTxQueue) {
        TxPacket pkt;
        pkt.data.assign(data, data + len);
        memcpy(&pkt.to, to, tolen);
        pkt.tolen = tolen;
        pkt.hasDest = true;
        txQueue_.push_back(std::move(pkt));
        stats_.txQueueCount++;
        if (txQueue_.size() > stats_.txQueuePeak) stats_.txQueuePeak = txQueue_.size();
        return static_cast<int>(len);
    }
    if (WSAGetLastError() == WSAEWOULDBLOCK) stats_.txQueueDrop++;
    return -1;
#else
    ssize_t n = ::sendto(fd_, data, len, MSG_DONTWAIT, to, tolen);
    if (n >= 0) { stats_.txSendSuccess++; return static_cast<int>(n); }
    // WOULDBLOCK: queue the packet
    if ((errno == EAGAIN || errno == EWOULDBLOCK) && txQueue_.size() < kMaxTxQueue) {
        TxPacket pkt;
        pkt.data.assign(data, data + len);
        memcpy(&pkt.to, to, tolen);
        pkt.tolen = tolen;
        pkt.hasDest = true;
        txQueue_.push_back(std::move(pkt));
        stats_.txQueueCount++;
        if (txQueue_.size() > stats_.txQueuePeak) stats_.txQueuePeak = txQueue_.size();
        return static_cast<int>(len);
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) stats_.txQueueDrop++;
    if (errno == EINTR) {
        n = ::sendto(fd_, data, len, MSG_DONTWAIT, to, tolen);
        return n >= 0 ? static_cast<int>(n) : -1;
    }
    return -1;
#endif
}

bool UdpSocket::DrainOnePacket(TxPacket& pkt) {
    if (fd_ < 0) return false;
#ifdef _WIN32
    int n;
    if (pkt.hasDest) {
        n = sendto(fd_, reinterpret_cast<const char*>(pkt.data.data()),
                   static_cast<int>(pkt.data.size()), 0,
                   reinterpret_cast<struct sockaddr*>(&pkt.to), pkt.tolen);
    } else {
        n = send(fd_, reinterpret_cast<const char*>(pkt.data.data()),
                 static_cast<int>(pkt.data.size()), 0);
    }
    if (n >= 0) { stats_.txDrainSuccess++; return true; }
    if (WSAGetLastError() == WSAEWOULDBLOCK) { stats_.txDrainWouldBlock++; return false; }
    stats_.txDrainError++;
    return false; // error — drop packet
#else
    ssize_t n;
    if (pkt.hasDest) {
        n = ::sendto(fd_, pkt.data.data(), pkt.data.size(), MSG_DONTWAIT,
                     reinterpret_cast<struct sockaddr*>(&pkt.to), pkt.tolen);
    } else {
        n = ::send(fd_, pkt.data.data(), pkt.data.size(), MSG_DONTWAIT);
    }
    if (n >= 0) { stats_.txDrainSuccess++; return true; }
    if (errno == EAGAIN || errno == EWOULDBLOCK) { stats_.txDrainWouldBlock++; return false; }
    stats_.txDrainError++;
    return false; // error — drop packet
#endif
}

size_t UdpSocket::DrainTxQueue() {
    while (!txQueue_.empty()) {
        auto& front = txQueue_.front();
        if (!DrainOnePacket(front)) break; // still WOULDBLOCK
        txQueue_.pop_front();
    }
    return txQueue_.size();
}

int UdpSocket::Recv(uint8_t* buf, size_t buflen) {
    if (fd_ < 0) return -1;
#ifdef _WIN32
    return recv(fd_, reinterpret_cast<char*>(buf),
                static_cast<int>(buflen), 0);
#else
    return ::recv(fd_, buf, buflen, 0);
#endif
}

int UdpSocket::RecvFrom(uint8_t* buf, size_t buflen,
                         struct sockaddr* from, socklen_t* fromlen) {
    if (fd_ < 0) return -1;
#ifdef _WIN32
    int n = recvfrom(fd_, reinterpret_cast<char*>(buf),
                     static_cast<int>(buflen), 0, from, fromlen);
    if (n > 0) stats_.rxPackets++;
    return n;
#else
    int n = ::recvfrom(fd_, buf, buflen, 0, from, fromlen);
    if (n > 0) stats_.rxPackets++;
    return n;
#endif
}

void UdpSocket::Close() {
    if (fd_ >= 0) {
#ifdef _WIN32
        closesocket(fd_);
#else
        ::close(fd_);
#endif
        fd_ = -1;
    }
}

std::string UdpSocket::LocalAddr() const {
    if (fd_ < 0) return "";
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(fd_, reinterpret_cast<struct sockaddr*>(&addr), &addrlen) < 0) return "";

    char buf[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr,
                  buf, sizeof(buf));
    } else if (addr.ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_addr,
                  buf, sizeof(buf));
    }
    return buf;
}

uint16_t UdpSocket::LocalPort() const {
    if (fd_ < 0) return 0;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(fd_, reinterpret_cast<struct sockaddr*>(&addr), &addrlen) < 0) return 0;

    if (addr.ss_family == AF_INET) {
        return ntohs(reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        return ntohs(reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port);
    }
    return 0;
}

bool UdpSocket::LocalSockaddr(struct sockaddr_storage* out, socklen_t* outLen) const {
    if (fd_ < 0) return false;
    socklen_t len = sizeof(*out);
    if (getsockname(fd_, reinterpret_cast<struct sockaddr*>(out), &len) < 0) return false;
    *outLen = len;
    return true;
}

bool UdpSocket::RemoteSockaddr(struct sockaddr_storage* out, socklen_t* outLen) const {
    if (fd_ < 0) return false;
    socklen_t len = sizeof(*out);
    if (getpeername(fd_, reinterpret_cast<struct sockaddr*>(out), &len) < 0) return false;
    *outLen = len;
    return true;
}

std::string UdpSocket::RemoteAddr() const {
    if (fd_ < 0) return "";
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);
    if (getpeername(fd_, reinterpret_cast<struct sockaddr*>(&addr), &addrlen) < 0) return "";

    char buf[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        inet_ntop(AF_INET, &reinterpret_cast<struct sockaddr_in*>(&addr)->sin_addr,
                  buf, sizeof(buf));
        return std::string(buf) + ":" + std::to_string(ntohs(
            reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port));
    } else if (addr.ss_family == AF_INET6) {
        inet_ntop(AF_INET6, &reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_addr,
                  buf, sizeof(buf));
        return std::string(buf) + ":" + std::to_string(ntohs(
            reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port));
    }
    return "";
}

UdpSocket::BufferSizes UdpSocket::GetActualBufferSizes() const {
    BufferSizes bs;
    if (fd_ < 0) return bs;
    socklen_t len = sizeof(bs.sndbuf);
    getsockopt(fd_, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char*>(&bs.sndbuf), &len);
    len = sizeof(bs.rcvbuf);
    getsockopt(fd_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&bs.rcvbuf), &len);
    return bs;
}

void UdpSocket::PrintStats(const char* tag) const {
    auto bs = GetActualBufferSizes();
    std::fprintf(stderr,
        "[%s] TX: success=%lu queue=%lu drop=%lu drain_ok=%lu drain_wb=%lu drain_err=%lu peak=%zu\n"
        "[%s] RX: packets=%lu\n"
        "[%s] SOCK: sndbuf=%d rcvbuf=%d\n",
        tag,
        (unsigned long)stats_.txSendSuccess,
        (unsigned long)stats_.txQueueCount,
        (unsigned long)stats_.txQueueDrop,
        (unsigned long)stats_.txDrainSuccess,
        (unsigned long)stats_.txDrainWouldBlock,
        (unsigned long)stats_.txDrainError,
        stats_.txQueuePeak,
        tag,
        (unsigned long)stats_.rxPackets,
        tag,
        bs.sndbuf, bs.rcvbuf);
}

} // namespace hy2::quic_backend
