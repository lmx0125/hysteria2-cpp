#include "hy2/quic_backend/udp_socket.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
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

namespace {
// Connect-path timing, printed only under HY2_QUIC_DEBUG. A handshake that
// takes hundreds of milliseconds on LOOPBACK is slow for reasons that have
// nothing to do with the network, and there is no other way to see which step
// owns the time - the app's node prober reports the total and nothing else.
bool SocketDiag() {
    static const bool v = std::getenv("HY2_QUIC_DEBUG") != nullptr;
    return v;
}
double MsSince(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now() - t0).count();
}

// SO_RCVBUF/SO_SNDBUF for every socket this file creates, in one place: Bind
// (listeners) and Connect (clients) used to carry separate copies of the same
// number, which is how they drift apart.
//
// The value is a *request per socket*, so it multiplies: pool_size 3 asked for
// 192MB across its three data sockets, and every node probe asked for another
// 64MB (probes dial a whole connection, see NodeProber).
//
// 32MB was picked for loopback, where the default 4MB overflowed while the
// sender ramped up cwnd during slow start. Re-measured 2026-10-12 with
// hy2_local_bench (10s download, one session, the three sizes alternated over
// three rounds): 8MB 50.75, 16MB 50.97, 32MB 50.86 MB/s - the spread within one
// size (44-54) is wider than the spread between them, so loopback cannot
// resolve this knob any more. 16MB is the middle landing spot: it halves the
// per-socket request (and with it the pool x sockets multiplier) while sitting
// inside the band that measured clean, and it still covers a cwnd-sized burst
// on a real line (~2x the ~4MB bandwidth-delay product of 190Mbps over 166ms).
//
// HY2_UDP_BUFSIZE_MB overrides it (A/B, and for loopback benches).
int UdpSocketBufferBytes() {
    static const int bytes = [] {
        int mb = 16;
        if (const char* env = std::getenv("HY2_UDP_BUFSIZE_MB")) {
            const int v = std::atoi(env);
            if (v > 0) mb = v;
        }
        if (mb < 1) mb = 1;
        if (mb > 64) mb = 64;
        return mb * 1024 * 1024;
    }();
    return bytes;
}
}  // namespace

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
    // See UdpSocketBufferBytes() for the size and why it is not 32MB.
    int bufSize = UdpSocketBufferBytes();
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

bool UdpSocket::Connect(const std::string& addr, uint16_t port,
                        const std::string& localBindAddr) {
    const auto tStart = std::chrono::steady_clock::now();
#ifdef _WIN32
    if (!InitWinsock()) return false;
#endif
    const auto tWsa = std::chrono::steady_clock::now();
    struct sockaddr_storage remoteAddr;
    socklen_t remoteLen;
    if (!ResolveAddress(addr, port, &remoteAddr, &remoteLen)) return false;
    const auto tResolve = std::chrono::steady_clock::now();

    fd_ = CreateNonBlockingSocket(remoteAddr.ss_family);
    if (fd_ < 0) return false;
    const auto tSock = std::chrono::steady_clock::now();

    // Optional local pinning: keeps the socket on the interface that owns the
    // given address even if the routing table later points elsewhere.
    if (!localBindAddr.empty()) {
        struct sockaddr_storage localAddr;
        socklen_t localLen;
        if (ResolveAddress(localBindAddr, 0, &localAddr, &localLen) &&
            localAddr.ss_family == remoteAddr.ss_family) {
            int reuseOpt = 1;
            setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const char*>(&reuseOpt), sizeof(reuseOpt));
            // Best effort: an unpinned socket still works, it is just
            // vulnerable to the TUN capturing its packets.
            ::bind(fd_, reinterpret_cast<struct sockaddr*>(&localAddr), localLen);
        }
    }

    // Generous buffers for bulk transfers on high-BDP or loopback paths - size
    // and rationale in UdpSocketBufferBytes().
    int bufSize = UdpSocketBufferBytes();
    setsockopt(fd_, SOL_SOCKET, SO_RCVBUF,
               reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));
    setsockopt(fd_, SOL_SOCKET, SO_SNDBUF,
               reinterpret_cast<const char*>(&bufSize), sizeof(bufSize));
    const auto tBuf = std::chrono::steady_clock::now();

    if (::connect(fd_, reinterpret_cast<struct sockaddr*>(&remoteAddr), remoteLen) < 0) {
        Close();
        return false;
    }
    if (SocketDiag()) {
        const auto tEnd = std::chrono::steady_clock::now();
        std::fprintf(stderr,
                     "[DIAG-SOCK] %s:%u wsa=%.1f resolve=%.1f socket=%.1f bufs=%.1f "
                     "connect=%.1f total=%.1f ms\n",
                     addr.c_str(), static_cast<unsigned>(port),
                     std::chrono::duration<double, std::milli>(tWsa - tStart).count(),
                     std::chrono::duration<double, std::milli>(tResolve - tWsa).count(),
                     std::chrono::duration<double, std::milli>(tSock - tResolve).count(),
                     std::chrono::duration<double, std::milli>(tBuf - tSock).count(),
                     std::chrono::duration<double, std::milli>(tEnd - tBuf).count(),
                     MsSince(tStart));
        std::fflush(stderr);
    }
    return true;
}

int UdpSocket::Send(const uint8_t* data, size_t len) {
    if (fd_ < 0) return -1;
#ifdef _WIN32
    int n = send(fd_, reinterpret_cast<const char*>(data),
                 static_cast<int>(len), 0);
    if (n >= 0) { txSendSuccess_.Inc(); return n; }
    int werr = WSAGetLastError();
    // WOULDBLOCK: queue the packet
    if (werr == WSAEWOULDBLOCK) {
        std::lock_guard<std::mutex> lk(txMu_);
        if (txQueue_.size() < kMaxTxQueue) {
            TxPacket pkt;
            pkt.data.assign(data, data + len);
            pkt.hasDest = false;
            EnqueueTxLocked(std::move(pkt));
            queueStats_.count++;
            if (txQueue_.size() > queueStats_.peak) queueStats_.peak = txQueue_.size();
            return static_cast<int>(len); // report success to caller
        }
        queueStats_.drop++;
        return -1;
    }
    if (std::getenv("HY2_BW_DIAG")) {
        std::fprintf(stderr, "[UDP-SEND] error=%d\n", werr);
    }
    return -1;
#else
    ssize_t n = ::send(fd_, data, len, MSG_DONTWAIT);
    if (n >= 0) { txSendSuccess_.Inc(); return static_cast<int>(n); }
    // WOULDBLOCK: queue the packet
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        std::lock_guard<std::mutex> lk(txMu_);
        if (txQueue_.size() < kMaxTxQueue) {
            TxPacket pkt;
            pkt.data.assign(data, data + len);
            pkt.hasDest = false;
            EnqueueTxLocked(std::move(pkt));
            queueStats_.count++;
            if (txQueue_.size() > queueStats_.peak) queueStats_.peak = txQueue_.size();
            return static_cast<int>(len); // report success to caller
        }
        queueStats_.drop++;
        return -1;
    }
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
    if (n >= 0) { txSendSuccess_.Inc(); return n; }
    // WOULDBLOCK: queue the packet
    if (WSAGetLastError() == WSAEWOULDBLOCK) {
        std::lock_guard<std::mutex> lk(txMu_);
        if (txQueue_.size() < kMaxTxQueue) {
            TxPacket pkt;
            pkt.data.assign(data, data + len);
            memcpy(&pkt.to, to, tolen);
            pkt.tolen = tolen;
            pkt.hasDest = true;
            EnqueueTxLocked(std::move(pkt));
            queueStats_.count++;
            if (txQueue_.size() > queueStats_.peak) queueStats_.peak = txQueue_.size();
            return static_cast<int>(len);
        }
        queueStats_.drop++;
        return -1;
    }
    return -1;
#else
    ssize_t n = ::sendto(fd_, data, len, MSG_DONTWAIT, to, tolen);
    if (n >= 0) { txSendSuccess_.Inc(); return static_cast<int>(n); }
    // WOULDBLOCK: queue the packet
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        std::lock_guard<std::mutex> lk(txMu_);
        if (txQueue_.size() < kMaxTxQueue) {
            TxPacket pkt;
            pkt.data.assign(data, data + len);
            memcpy(&pkt.to, to, tolen);
            pkt.tolen = tolen;
            pkt.hasDest = true;
            EnqueueTxLocked(std::move(pkt));
            queueStats_.count++;
            if (txQueue_.size() > queueStats_.peak) queueStats_.peak = txQueue_.size();
            return static_cast<int>(len);
        }
        queueStats_.drop++;
        return -1;
    }
    if (errno == EINTR) {
        n = ::sendto(fd_, data, len, MSG_DONTWAIT, to, tolen);
        return n >= 0 ? static_cast<int>(n) : -1;
    }
    return -1;
#endif
}

// UDP_SEND_MSG_SIZE lives in ws2ipdef.h (pulled in by ws2tcpip.h) on the
// Windows 10 2004+ SDKs. Define it locally so an older SDK still compiles -
// EnableTxSegmentation() probes the option at runtime and fails cleanly there.
#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE 2
#endif

bool UdpSocket::EnableTxSegmentation(size_t segLen) {
#ifdef _WIN32
    if (fd_ < 0 || segLen == 0) return false;
    // Escape hatch: segmentation offload is a driver/NIC feature and a buggy
    // implementation would corrupt packets rather than fail loudly, so it must
    // be possible to turn off without a rebuild.
    static const bool disabled = std::getenv("HY2_NO_TX_SEG") != nullptr;
    if (disabled) return false;
    // The option is PER SOCKET, and the server shares one socket across every
    // connection. So the first size wins: letting a second connection re-set it
    // would re-segment the first connection's in-flight batch by the wrong
    // boundary and corrupt its packets. A connection whose packets do not match
    // the established size simply never batches.
    if (txSegEnabled_) return txSegLen_ == segLen;
    DWORD want = static_cast<DWORD>(segLen);
    if (setsockopt(fd_, IPPROTO_UDP, UDP_SEND_MSG_SIZE,
                   reinterpret_cast<const char*>(&want), sizeof(want)) != 0) {
        return false;
    }
    // Read it back: a stack that does not implement the offload may accept the
    // setsockopt and ignore it, and silently sending an oversized datagram
    // would be far worse than not batching at all.
    DWORD got = 0;
    int gotLen = sizeof(got);
    if (getsockopt(fd_, IPPROTO_UDP, UDP_SEND_MSG_SIZE,
                   reinterpret_cast<char*>(&got), &gotLen) != 0 ||
        got != want) {
        return false;
    }
    txSegLen_ = segLen;
    txSegEnabled_ = true;
    return true;
#else
    (void)segLen;
    return false;
#endif
}

int UdpSocket::SendSegmented(const uint8_t* data, size_t totalLen,
                             const struct sockaddr* to, socklen_t tolen) {
#ifdef _WIN32
    if (fd_ < 0 || !txSegEnabled_ || txSegLen_ == 0) return -1;
    if (totalLen == 0 || totalLen % txSegLen_ != 0) return -1;

    WSABUF wb;
    wb.buf = const_cast<CHAR*>(reinterpret_cast<const CHAR*>(data));
    wb.len = static_cast<ULONG>(totalLen);

    WSAMSG msg;
    memset(&msg, 0, sizeof(msg));
    msg.name = const_cast<LPSOCKADDR>(to);
    msg.namelen = to ? static_cast<INT>(tolen) : 0;
    msg.lpBuffers = &wb;
    msg.dwBufferCount = 1;

    DWORD sent = 0;
    if (WSASendMsg(static_cast<SOCKET>(fd_), &msg, 0, &sent, nullptr, nullptr) ==
        SOCKET_ERROR) {
        return -1;
    }
    if (sent > 0) {
        // Counted per datagram, like the single-packet path, so the existing
        // stats stay comparable across both.
        txSendSuccess_.Add(sent / txSegLen_);
    }
    return static_cast<int>(sent);
#else
    (void)data; (void)totalLen; (void)to; (void)tolen;
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
    if (n >= 0) { txDrainSuccess_.Inc(); return true; }
    if (WSAGetLastError() == WSAEWOULDBLOCK) { txDrainWouldBlock_.Inc(); return false; }
    txDrainError_.Inc();
    return false; // error — drop packet
#else
    ssize_t n;
    if (pkt.hasDest) {
        n = ::sendto(fd_, pkt.data.data(), pkt.data.size(), MSG_DONTWAIT,
                     reinterpret_cast<struct sockaddr*>(&pkt.to), pkt.tolen);
    } else {
        n = ::send(fd_, pkt.data.data(), pkt.data.size(), MSG_DONTWAIT);
    }
    if (n >= 0) { txDrainSuccess_.Inc(); return true; }
    if (errno == EAGAIN || errno == EWOULDBLOCK) { txDrainWouldBlock_.Inc(); return false; }
    txDrainError_.Inc();
    return false; // error — drop packet
#endif
}

void UdpSocket::EnqueueTxLocked(TxPacket&& pkt) {
    txQueue_.push_back(std::move(pkt));
    txQueued_.store(true, std::memory_order_release);
}

void UdpSocket::EnqueueForTest(const uint8_t* data, size_t len,
                               const struct sockaddr* to, socklen_t tolen) {
    TxPacket pkt;
    pkt.data.assign(data, data + len);
    if (to != nullptr) {
        memcpy(&pkt.to, to, tolen);
        pkt.tolen = tolen;
        pkt.hasDest = true;
    } else {
        pkt.hasDest = false;
    }
    std::lock_guard<std::mutex> lk(txMu_);
    EnqueueTxLocked(std::move(pkt));
}

size_t UdpSocket::DrainTxQueue() {
    // Uncontended fast path: the queue is almost always empty (a successful
    // sendto never queues anything), and txMu_ is shared by every connection
    // on this listener. See txQueued_ in the header.
    if (!txQueued_.load(std::memory_order_acquire)) return 0;
    for (;;) {
        TxPacket pkt;
        {
            std::lock_guard<std::mutex> lk(txMu_);
            if (txQueue_.empty()) {
                txQueued_.store(false, std::memory_order_release);
                return 0;
            }
            pkt = std::move(txQueue_.front());
            txQueue_.pop_front();
        }
        if (!DrainOnePacket(pkt)) {
            // Still WOULDBLOCK: put it back and stop.
            std::lock_guard<std::mutex> lk(txMu_);
            txQueue_.push_front(std::move(pkt));
            txQueued_.store(true, std::memory_order_release);
            return txQueue_.size();
        }
    }
}

bool UdpSocket::HasQueuedPackets() const {
    return txQueued_.load(std::memory_order_acquire);
}

UdpSocket::Stats UdpSocket::GetStats() const {
    Stats out;
    {
        std::lock_guard<std::mutex> lk(txMu_);
        out.txQueueCount = queueStats_.count;
        out.txQueueDrop = queueStats_.drop;
        out.txQueuePeak = queueStats_.peak;
    }
    // The per-packet counters are striped relaxed atomics: no lock is needed and
    // none is taken, so reading them never perturbs the send path.
    out.txSendSuccess = txSendSuccess_.Sum();
    out.txDrainSuccess = txDrainSuccess_.Sum();
    out.txDrainWouldBlock = txDrainWouldBlock_.Sum();
    out.txDrainError = txDrainError_.Sum();
    out.rxPackets = rxPackets_.Sum();
    return out;
}

void UdpSocket::ResetStats() {
    std::lock_guard<std::mutex> lk(txMu_);
    queueStats_ = {};
    txSendSuccess_.Reset();
    txDrainSuccess_.Reset();
    txDrainWouldBlock_.Reset();
    txDrainError_.Reset();
    rxPackets_.Reset();
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
    if (n > 0) rxPackets_.Inc();
    return n;
#else
    int n = ::recvfrom(fd_, buf, buflen, 0, from, fromlen);
    if (n > 0) rxPackets_.Inc();
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
    const Stats stats = GetStats();
    std::fprintf(stderr,
        "[%s] TX: success=%lu queue=%lu drop=%lu drain_ok=%lu drain_wb=%lu drain_err=%lu peak=%zu\n"
        "[%s] RX: packets=%lu\n"
        "[%s] SOCK: sndbuf=%d rcvbuf=%d\n",
        tag,
        (unsigned long)stats.txSendSuccess,
        (unsigned long)stats.txQueueCount,
        (unsigned long)stats.txQueueDrop,
        (unsigned long)stats.txDrainSuccess,
        (unsigned long)stats.txDrainWouldBlock,
        (unsigned long)stats.txDrainError,
        stats.txQueuePeak,
        tag,
        (unsigned long)stats.rxPackets,
        tag,
        bs.sndbuf, bs.rcvbuf);
}

} // namespace hy2::quic_backend
