// direct.cpp - Direct outbound: TCP/UDP dial using OS sockets.
// Rewrite of extras/outbounds/ob_direct.go.
// Includes TCP Fast Open (TFO) support for Linux.
#include "hy2/outbounds/direct.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <vector>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <deque>
#include <unordered_map>

namespace hy2::outbounds {

namespace {

#ifdef _WIN32
static bool g_wsaInit = [] {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0;
}();
#else
static bool g_wsaInit = true;
#endif

constexpr int kDialTimeoutSec = 10;

// Nagle would hold a small segment until the previous one is acknowledged - on
// Windows that is the 200 ms delayed-ACK timer, and a proxied request/response
// stream pays it on every round trip. The relay writes whole buffers, so there
// is nothing here worth coalescing.
void setTcpNoDelay(int fd) {
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&on), sizeof(on));
}

// Test hook counter (see DirectOutboundUdpResolveCount in direct.hpp).
std::atomic<uint64_t> g_udpResolveCalls{0};

// Test hook counter for the TCP path (see DirectOutboundTcpResolveCount).
std::atomic<uint64_t> g_tcpResolveCalls{0};


// ---------------------------------------------------------------------------
// TCP Fast Open (TFO) support

#ifdef __linux__
// Check if TFO is supported by the kernel (Linux 4.11+)
static bool checkTfoSupport() {
    // Try to create a socket with TFO enabled
    // If it fails, TFO is not supported
    int fd = static_cast<int>(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (fd < 0) return false;

    int enable = 1;
    int result = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable));

#ifdef _WIN32
    closesocket(fd);
#else
    ::close(fd);
#endif

    return result == 0;
}

// Enable TFO on a socket
static bool enableTfo(int fd) {
    int enable = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable)) == 0;
}

// TFO connect: send data during SYN
int connectWithTfo(int fd, const struct sockaddr* addr, socklen_t addrlen,
                   const uint8_t* data, size_t dataLen) {
    // Use sendto with MSG_FASTOPEN flag
    ssize_t sent = sendto(fd, reinterpret_cast<const char*>(data),
                          static_cast<int>(dataLen), MSG_FASTOPEN,
                          addr, addrlen);
    if (sent >= 0) {
        return 0; // Success
    }

    // If EOPNOTSUPP, fall back to regular connect
    if (errno == EOPNOTSUPP || errno == EPROTONOSUPPORT) {
        return ::connect(fd, addr, addrlen);
    }

    return -1;
}
#endif // __linux__

// Check if TFO is available (cached)
static bool isTfoAvailable() {
#ifdef __linux__
    static bool available = checkTfoSupport();
    return available;
#else
    return false;
#endif
}

// ---------------------------------------------------------------------------
// TcpConn - IConn over a real socket fd
// Supports TCP Fast Open (TFO) for sending initial data during handshake

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
        if (fd_ < 0) throw std::runtime_error("tcp conn closed");
        size_t off = 0;
        while (off < n) {
            int w = static_cast<int>(::send(fd_,
                                            reinterpret_cast<const char*>(p + off),
                                            static_cast<int>(n - off), 0));
            if (w <= 0) throw std::runtime_error("tcp send failed");
            off += static_cast<size_t>(w);
        }
    }

    // Write with TFO support - sends data during SYN on Linux
    // Returns true if TFO was used, false for regular send
    bool WriteWithTfo(const uint8_t* p, size_t n, const struct sockaddr* addr,
                      socklen_t addrlen) {
        if (fd_ < 0) return false;

#ifdef __linux__
        if (isTfoAvailable() && p && n > 0) {
            ssize_t sent = sendto(fd_, reinterpret_cast<const char*>(p),
                                  static_cast<int>(n), MSG_FASTOPEN,
                                  addr, addrlen);
            if (sent >= 0) {
                return true; // TFO used successfully
            }
            // If TFO fails, fall back to regular send
        }
#endif

        // Regular send
        Write(p, n);
        return false;
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

    int GetFd() const { return fd_; }

private:
    int fd_ = -1;
};

// ---------------------------------------------------------------------------
// resolveHost - DNS resolution using getaddrinfo

struct ResolvedAddr {
    std::string ipv4; // non-empty if IPv4 found
    std::string ipv6; // non-empty if IPv6 found
};

ResolvedAddr resolveHost(const std::string& host, uint16_t port) {
    ResolvedAddr result;
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        return result;
    }

    for (auto* rp = res; rp != nullptr; rp = rp->ai_next) {
        char addrBuf[INET6_ADDRSTRLEN] = {};
        if (rp->ai_family == AF_INET && result.ipv4.empty()) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, addrBuf, sizeof(addrBuf));
            result.ipv4 = addrBuf;
        } else if (rp->ai_family == AF_INET6 && result.ipv6.empty()) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, addrBuf, sizeof(addrBuf));
            result.ipv6 = addrBuf;
        }
        if (!result.ipv4.empty() && !result.ipv6.empty()) break;
    }
    freeaddrinfo(res);
    return result;
}

// ---------------------------------------------------------------------------
// TCP-side hostname cache.
//
// The UDP path got this cache (see ResolveTarget below) after a measurement
// showed the resolver on the datagram path; the TCP path - which dials a fresh
// destination for every proxied connection - did not, so a browser opening a
// page against one hostname paid a blocking getaddrinfo() per connection, on
// the relay worker thread. Only real hostnames are cached: a numeric literal
// is already handled without the resolver by tryParseIP, which is the common
// case, and caching it would evict the entry that actually matters.
//
// Deliberately bounded and tiny (no TTL): this is a connection-rate cache for
// a proxy relaying one dial at a time, not a general resolver. 128 entries is
// far below any real browsing working set, so an entry that keeps getting hit
// survives, and DNS changes are picked up once the working set churns past it.
constexpr size_t kTcpResolveCacheMax = 128;

struct TcpResolveCache {
    std::mutex mu;
    std::unordered_map<std::string, ResolvedAddr> byHost;  // key: "host:port"
    std::deque<std::string> order;                          // FIFO for eviction
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> misses{0};

    // Returns true and fills out on a hit.
    bool Lookup(const std::string& key, ResolvedAddr& out) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = byHost.find(key);
        if (it == byHost.end()) {
            misses.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        out = it->second;
        hits.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    void Store(const std::string& key, const ResolvedAddr& value) {
        std::lock_guard<std::mutex> lk(mu);
        if (byHost.find(key) != byHost.end()) return;
        if (byHost.size() >= kTcpResolveCacheMax && !order.empty()) {
            byHost.erase(order.front());
            order.pop_front();
        }
        byHost.emplace(key, value);
        order.push_back(key);
    }

    void Clear() {
        std::lock_guard<std::mutex> lk(mu);
        byHost.clear();
        order.clear();
    }
};

TcpResolveCache& TcpResolve() {
    static TcpResolveCache cache;
    return cache;
}

// tryParseIP - check if host is already an IP address
bool tryParseIP(const std::string& host, ResolvedAddr& out) {
    // Try IPv4
    struct in_addr addr4{};
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) {
        out.ipv4 = host;
        return true;
    }
    // Try IPv6
    struct in6_addr addr6{};
    if (inet_pton(AF_INET6, host.c_str(), &addr6) == 1) {
        out.ipv6 = host;
        return true;
    }
    return false;
}

// dialTCP - connect to ip:port with timeout
// Supports TCP Fast Open (TFO) on Linux when available
int dialTCP(const std::string& ip, uint16_t port, int timeoutSec) {
    int family = ip.find(':') == std::string::npos ? AF_INET : AF_INET6;
    int fd = static_cast<int>(socket(family, SOCK_STREAM, IPPROTO_TCP));
    if (fd < 0) return -1;

    // Build address
    struct sockaddr_storage addr{};
    socklen_t addrLen = 0;
    if (family == AF_INET) {
        auto* sin = reinterpret_cast<struct sockaddr_in*>(&addr);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &sin->sin_addr);
        addrLen = sizeof(*sin);
    } else {
        auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(port);
        inet_pton(AF_INET6, ip.c_str(), &sin6->sin6_addr);
        addrLen = sizeof(*sin6);
    }

#ifdef _WIN32
    // Non-blocking connect with timeout via select (Windows doesn't support TFO)
    u_long nb = 1;
    ioctlsocket(fd, FIONBIO, &nb);
    int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), addrLen);
    if (rc < 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        closesocket(fd);
        return -1;
    }
    fd_set wf;
    FD_ZERO(&wf);
    FD_SET(static_cast<SOCKET>(fd), &wf);
    // Windows reports a *failed* connect in the EXCEPTION set, not the write
    // set. Watching writefds alone made every refused/unreachable target wait
    // out the full timeout (measured: 10 s for 127.0.0.1:1) before the server
    // answered "dial failed" - the client saw a 10 s stall per dead target.
    fd_set ef;
    FD_ZERO(&ef);
    FD_SET(static_cast<SOCKET>(fd), &ef);
    struct timeval tv{timeoutSec, 0};
    if (select(0, nullptr, &wf, &ef, &tv) <= 0) {
        closesocket(fd);
        return -1;
    }
    int err = 0;
    int len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
    if (err != 0) {
        closesocket(fd);
        return -1;
    }
    nb = 0;
    ioctlsocket(fd, FIONBIO, &nb);
#else
    // Set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

#ifdef __linux__
    // Try TCP Fast Open (TFO) on Linux
    if (isTfoAvailable()) {
        // Enable TFO on the socket
        enableTfo(fd);

        // Use sendto with MSG_FASTOPEN to initiate connection with data
        // For initial connection, we send empty data (just the SYN with TFO cookie request)
        int rc = connectWithTfo(fd, reinterpret_cast<struct sockaddr*>(&addr),
                                addrLen, nullptr, 0);
        if (rc == 0 || (rc < 0 && errno == EINPROGRESS)) {
            // Connection initiated (or in progress)
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(fd, &wf);
            struct timeval tv{timeoutSec, 0};
            if (select(fd + 1, nullptr, &wf, nullptr, &tv) <= 0) {
                ::close(fd);
                return -1;
            }
            int err = 0;
            socklen_t len = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err != 0) {
                ::close(fd);
                return -1;
            }
            // Restore blocking
            fcntl(fd, F_SETFL, flags);
            setTcpNoDelay(fd);
            return fd;
        }
        // TFO failed, fall back to regular connect
    }
#endif // __linux__

    // Regular connect (non-TFO)
    int rc = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), addrLen);
    if (rc < 0 && errno != EINPROGRESS) {
        ::close(fd);
        return -1;
    }
    if (rc < 0) {
        fd_set wf;
        FD_ZERO(&wf);
        FD_SET(fd, &wf);
        struct timeval tv{timeoutSec, 0};
        if (select(fd + 1, nullptr, &wf, nullptr, &tv) <= 0) {
            ::close(fd);
            return -1;
        }
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            ::close(fd);
            return -1;
        }
    }
    // Restore blocking
    fcntl(fd, F_SETFL, flags);
#endif

    setTcpNoDelay(fd);
    return fd;
}

// dialTCPOrIPv6Fallback - try IPv4 first, fallback to IPv6 (or vice versa)
// Returns first successful connection, closing the other if both succeed.
int dialDualStack(const std::string& ipv4, const std::string& ipv6,
                  uint16_t port, bool preferIPv6) {
    // If only one is available, just use it
    if (ipv4.empty() && ipv6.empty()) return -1;
    if (ipv6.empty()) return dialTCP(ipv4, port, kDialTimeoutSec);
    if (ipv4.empty()) return dialTCP(ipv6, port, kDialTimeoutSec);

    // Both available - race them
    std::mutex mu;
    std::condition_variable cv;
    std::vector<int> results(2, -1);
    int ready = 0;

    auto dialThread = [&](int idx, const std::string& ip) {
        int fd = dialTCP(ip, port, kDialTimeoutSec);
        {
            std::lock_guard<std::mutex> lk(mu);
            results[idx] = fd;
            ready++;
        }
        cv.notify_one();
    };

    int primary = preferIPv6 ? 1 : 0;
    int secondary = 1 - primary;

    std::thread t1(dialThread, primary, preferIPv6 ? ipv6 : ipv4);
    std::thread t2(dialThread, secondary, preferIPv6 ? ipv4 : ipv6);

    // Wait for first result
    {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&] { return ready >= 1; });
    }

    int firstIdx = results[primary] >= 0 ? primary : secondary;
    int firstFd = results[firstIdx];

    // Wait for second result (it may already be done)
    {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&] { return ready >= 2; });
    }

    t1.join();
    t2.join();

    // If first succeeded, close the other
    int secondIdx = 1 - firstIdx;
    if (firstFd >= 0 && results[secondIdx] >= 0) {
#ifdef _WIN32
        closesocket(results[secondIdx]);
#else
        ::close(results[secondIdx]);
#endif
    }

    // If first failed, try second
    if (firstFd < 0) {
        return results[secondIdx];
    }
    return firstFd;
}

// ---------------------------------------------------------------------------
// UdpConn - IUdpConn over a real socket fd

class UdpConn : public server::IUdpConn {
public:
    UdpConn(int fd, const std::string& remoteHost, uint16_t remotePort)
        : fd_(fd), remoteHost_(remoteHost), remotePort_(remotePort) {
        // Start pump thread
        pumpThread_ = std::thread([this] { pumpLoop(); });
    }

    ~UdpConn() override { Close(); }

    size_t ReadFrom(uint8_t* buf, size_t len, std::string& addr) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [this] { return !queue_.empty() || closed_; });
        if (closed_ || queue_.empty()) return 0;
        auto& item = queue_.front();
        size_t n = std::min(len, item.first.size());
        std::memcpy(buf, item.first.data(), n);
        addr = item.second;
        queue_.pop_front();
        return n;
    }

    void WriteTo(const uint8_t* buf, size_t len, const std::string& addr) override {
        if (fd_ < 0) return;

        struct sockaddr_storage sa{};
        socklen_t saLen = 0;
        if (!ResolveTarget(addr, &sa, &saLen)) return;

        ::sendto(fd_, reinterpret_cast<const char*>(buf), static_cast<int>(len), 0,
                 reinterpret_cast<const struct sockaddr*>(&sa), static_cast<int>(saLen));
    }

    void Close() override {
        std::lock_guard<std::mutex> lk(mu_);
        if (closed_) return;
        closed_ = true;
        if (fd_ >= 0) {
#ifdef _WIN32
            closesocket(fd_);
#else
            ::close(fd_);
#endif
            fd_ = -1;
        }
        cv_.notify_all();
        if (pumpThread_.joinable()) pumpThread_.join();
    }

private:
    void pumpLoop() {
        uint8_t buf[65536];
        for (;;) {
            struct sockaddr_storage from{};
            socklen_t fromlen = sizeof(from);
            int n = ::recvfrom(fd_, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                               reinterpret_cast<struct sockaddr*>(&from), &fromlen);
            if (n <= 0) break;

            char ip[INET6_ADDRSTRLEN] = {};
            uint16_t port = 0;
            if (from.ss_family == AF_INET) {
                auto* sin = reinterpret_cast<struct sockaddr_in*>(&from);
                inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
                port = ntohs(sin->sin_port);
            } else if (from.ss_family == AF_INET6) {
                auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(&from);
                inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
                port = ntohs(sin6->sin6_port);
            }

            std::string fromAddr = std::string(ip) + ":" + std::to_string(port);
            std::lock_guard<std::mutex> lk(mu_);
            if (closed_) break;
            queue_.push_back({std::vector<uint8_t>(buf, buf + n), std::move(fromAddr)});
            // Single consumer (ReadFrom): waking everyone just to have one of
            // them re-park is pure context switching.
            cv_.notify_one();
        }
    }

    // ResolveTarget fills *sa/*saLen with the destination for addr.
    //
    // This used to call getaddrinfo() on every datagram: WriteTo is the UDP
    // send path, so at 10k datagrams/s that was 10k resolver calls, each with
    // its own addrinfo list allocation, plus two std::string temporaries - and
    // for a hostname it was a blocking DNS lookup per packet, with the address
    // coming from the client's datagram (a DoS amplifier). A session's target
    // is constant, so the result is cached: after the first datagram this is a
    // string compare. Numeric addresses (the common case) are resolved with
    // AI_NUMERICHOST, which never touches the resolver; only a real hostname
    // falls back to a full lookup, and only on a cache miss.
    bool ResolveTarget(const std::string& addr, struct sockaddr_storage* sa, socklen_t* saLen) {
        std::lock_guard<std::mutex> lk(addrMu_);
        if (addrCacheValid_ && addr == addrCacheKey_) {
            *sa = addrCacheSa_;
            *saLen = addrCacheLen_;
            return true;
        }

        const auto colon = addr.rfind(':');
        if (colon == std::string::npos) return false;
        const std::string host = addr.substr(0, colon);
        const uint16_t port = static_cast<uint16_t>(std::atoi(addr.c_str() + colon + 1));

        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_NUMERICHOST;
        struct addrinfo* res = nullptr;
        const std::string portStr = std::to_string(port);
        g_udpResolveCalls.fetch_add(1, std::memory_order_relaxed);
        if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
            // Not a numeric literal - pay for a real lookup (once per address).
            res = nullptr;
            hints.ai_flags = 0;
            g_udpResolveCalls.fetch_add(1, std::memory_order_relaxed);
            if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
                return false;
            }
        }
        if (res->ai_addrlen > sizeof(*sa)) {
            freeaddrinfo(res);
            return false;
        }
        std::memcpy(sa, res->ai_addr, res->ai_addrlen);
        *saLen = static_cast<socklen_t>(res->ai_addrlen);
        freeaddrinfo(res);

        addrCacheKey_ = addr;
        addrCacheSa_ = *sa;
        addrCacheLen_ = *saLen;
        addrCacheValid_ = true;
        return true;
    }

    int fd_;
    std::string remoteHost_;
    uint16_t remotePort_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::pair<std::vector<uint8_t>, std::string>> queue_;
    bool closed_ = false;
    std::thread pumpThread_;

    // Destination cache, guarded by its own mutex so a cache miss (which may
    // block in the resolver) never holds mu_ - ReadFrom/Close/pumpLoop need it.
    std::mutex addrMu_;
    std::string addrCacheKey_;
    struct sockaddr_storage addrCacheSa_{};
    socklen_t addrCacheLen_ = 0;
    bool addrCacheValid_ = false;
};

} // anonymous namespace

uint64_t DirectOutboundUdpResolveCount() {
    return g_udpResolveCalls.load(std::memory_order_relaxed);
}

uint64_t DirectOutboundTcpResolveCount() {
    return g_tcpResolveCalls.load(std::memory_order_relaxed);
}

void DirectOutboundResetTcpResolveCache() {
    TcpResolve().Clear();
    g_tcpResolveCalls.store(0, std::memory_order_relaxed);
}

// ---------------------------------------------------------------------------
// DirectOutbound

DirectOutbound::DirectOutbound(DirectOutboundMode mode) : mode_(mode) {}

std::shared_ptr<server::IConn> DirectOutbound::TCP(const std::string& reqAddr) {
    if (!g_wsaInit) throw std::runtime_error("socket init failed");

    // Split host:port
    auto colon = reqAddr.rfind(':');
    if (colon == std::string::npos) {
        throw std::runtime_error("invalid address: " + reqAddr);
    }
    std::string host = reqAddr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(reqAddr.c_str() + colon + 1));

    // Resolve. A numeric literal never touches the resolver; a hostname is
    // cached, because every proxied connection dials a fresh destination and
    // this call blocks the relay worker thread.
    ResolvedAddr resolved;
    if (!tryParseIP(host, resolved)) {
        const std::string key = host + ":" + std::to_string(port);
        if (!TcpResolve().Lookup(key, resolved)) {
            g_tcpResolveCalls.fetch_add(1, std::memory_order_relaxed);
            resolved = resolveHost(host, port);
            // Only cache a success: caching a failure would pin a transient
            // resolver error for the whole working set.
            if (!resolved.ipv4.empty() || !resolved.ipv6.empty()) {
                TcpResolve().Store(key, resolved);
            }
        }
    }

    if (resolved.ipv4.empty() && resolved.ipv6.empty()) {
        throw std::runtime_error("no address available for: " + host);
    }

    int fd = -1;
    switch (mode_) {
    case DirectOutboundMode::Auto:
        if (!resolved.ipv4.empty() && !resolved.ipv6.empty()) {
            fd = dialDualStack(resolved.ipv4, resolved.ipv6, port, false);
        } else if (!resolved.ipv4.empty()) {
            fd = dialTCP(resolved.ipv4, port, kDialTimeoutSec);
        } else {
            fd = dialTCP(resolved.ipv6, port, kDialTimeoutSec);
        }
        break;
    case DirectOutboundMode::IPv6Prefer:
        if (!resolved.ipv6.empty()) {
            fd = dialTCP(resolved.ipv6, port, kDialTimeoutSec);
        } else {
            fd = dialTCP(resolved.ipv4, port, kDialTimeoutSec);
        }
        break;
    case DirectOutboundMode::IPv4Prefer:
        if (!resolved.ipv4.empty()) {
            fd = dialTCP(resolved.ipv4, port, kDialTimeoutSec);
        } else {
            fd = dialTCP(resolved.ipv6, port, kDialTimeoutSec);
        }
        break;
    case DirectOutboundMode::IPv6Only:
        if (resolved.ipv6.empty()) {
            throw std::runtime_error("no IPv6 address available for: " + host);
        }
        fd = dialTCP(resolved.ipv6, port, kDialTimeoutSec);
        break;
    case DirectOutboundMode::IPv4Only:
        if (resolved.ipv4.empty()) {
            throw std::runtime_error("no IPv4 address available for: " + host);
        }
        fd = dialTCP(resolved.ipv4, port, kDialTimeoutSec);
        break;
    }

    if (fd < 0) {
        throw std::runtime_error("dial failed for: " + reqAddr);
    }
    return std::make_shared<TcpConn>(fd);
}

std::shared_ptr<server::IUdpConn> DirectOutbound::UDP(const std::string& reqAddr) {
    if (!g_wsaInit) throw std::runtime_error("socket init failed");

    // Split host:port
    auto colon = reqAddr.rfind(':');
    if (colon == std::string::npos) {
        throw std::runtime_error("invalid address: " + reqAddr);
    }
    std::string host = reqAddr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(reqAddr.c_str() + colon + 1));

    // Create UDP socket
    int fd = static_cast<int>(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (fd < 0) {
        throw std::runtime_error("UDP socket create failed");
    }

    // Bind to ephemeral port
    struct sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = INADDR_ANY;
    bindAddr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&bindAddr), sizeof(bindAddr)) < 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        throw std::runtime_error("UDP bind failed");
    }

    return std::make_shared<UdpConn>(fd, host, port);
}

bool DirectOutbound::CheckUDP(const std::string& /*reqAddr*/) {
    return true;
}

} // namespace hy2::outbounds
