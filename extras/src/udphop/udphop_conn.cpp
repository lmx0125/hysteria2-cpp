// udphop_conn.cpp - UDP port hopping connection.
// Rewrite of extras/transport/udphop/conn.go.
#include "hy2/udphop/udphop_conn.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

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

namespace hy2::udphop {

namespace {

#ifdef _WIN32
static bool g_wsaInit = [] {
    WSADATA w;
    return WSAStartup(MAKEWORD(2, 2), &w) == 0;
}();
#else
static bool g_wsaInit = true;
#endif

// Create a UDP socket bound to an ephemeral port
int createUdpSocket() {
    if (!g_wsaInit) return -1;
    int fd = static_cast<int>(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    if (fd < 0) return -1;

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        ::close(fd);
#endif
        return -1;
    }
    // Set receive timeout so recvLoop can check for close
#ifdef _WIN32
    DWORD timeout = 1000; // 1 second
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    struct timeval tv{1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    return fd;
}

// Parse "ip:port" into sockaddr_in
bool parseSockaddr(const std::string& addr, struct sockaddr_in& sa) {
    auto colon = addr.rfind(':');
    if (colon == std::string::npos) return false;
    std::string host = addr.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(addr.c_str() + colon + 1));

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) != 1) return false;
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// UdpHopConn

UdpHopConn::~UdpHopConn() {
    Close();
}

void UdpHopConn::recvLoop(int fd) {
    uint8_t buf[2048];
    while (!closed_.load(std::memory_order_acquire)) {
        struct sockaddr_in from{};
        socklen_t fromLen = sizeof(from);
        int n = static_cast<int>(::recvfrom(fd, reinterpret_cast<char*>(buf),
                                            sizeof(buf), 0,
                                            reinterpret_cast<struct sockaddr*>(&from),
                                            &fromLen));
        if (n <= 0) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAETIMEDOUT) continue;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
#endif
            // Socket closed or error - exit loop
            break;
        }

        char ip[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        std::string fromAddr = std::string(ip) + ":" + std::to_string(ntohs(from.sin_port));

        RecvPacket pkt;
        pkt.data.assign(buf, buf + n);
        pkt.from = std::move(fromAddr);

        std::lock_guard<std::mutex> lk(recvMutex_);
        if (recvQueue_.size() >= kMaxQueueSize) {
            recvQueue_.pop_front(); // drop oldest
        }
        recvQueue_.push_back(std::move(pkt));
        recvCv_.notify_one();
    }
}

void UdpHopConn::hopLoop() {
    while (!closed_.load(std::memory_order_acquire)) {
        int64_t interval = nextHopInterval();
        // Sleep in small increments to check for close
        for (int64_t i = 0; i < interval / 1000000 && !closed_.load(std::memory_order_acquire); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (closed_.load(std::memory_order_acquire)) break;
        hop();
    }
}

int64_t UdpHopConn::nextHopInterval() {
    if (hopInterval_.minNs == hopInterval_.maxNs) return hopInterval_.minNs;
    std::uniform_int_distribution<int64_t> dist(hopInterval_.minNs, hopInterval_.maxNs);
    return dist(rng_);
}

void UdpHopConn::hop() {
    std::lock_guard<std::mutex> lk(connMutex_);
    if (closed_.load(std::memory_order_acquire)) return;

    int newFd = createUdpSocket();
    if (newFd < 0) return; // temporary failure, skip this hop

    // Close prev, move current to prev, set new as current
    if (prevFd_ >= 0) {
#ifdef _WIN32
        closesocket(prevFd_);
#else
        ::close(prevFd_);
#endif
    }
    prevFd_ = currentFd_;
    currentFd_ = newFd;

    // Pick a new random address
    if (!addr_.Ports.empty()) {
        std::uniform_int_distribution<size_t> dist(0, addr_.Ports.size() - 1);
        addrIndex_ = dist(rng_);
    }

    // Start recv loop on new socket
    if (recvThread_.joinable()) recvThread_.detach();
    recvThread_ = std::thread([this, newFd] { recvLoop(newFd); });
}

size_t UdpHopConn::ReadFrom(uint8_t* buf, size_t len, std::string& addr) {
    std::unique_lock<std::mutex> lk(recvMutex_);
    recvCv_.wait(lk, [this] { return !recvQueue_.empty() || closed_.load(std::memory_order_acquire); });

    if (closed_.load(std::memory_order_acquire) && recvQueue_.empty()) return 0;

    auto pkt = std::move(recvQueue_.front());
    recvQueue_.pop_front();
    lk.unlock();

    size_t n = std::min(len, pkt.data.size());
    std::memcpy(buf, pkt.data.data(), n);
    addr = addr_.String(); // always return the original server address
    return n;
}

void UdpHopConn::WriteTo(const uint8_t* buf, size_t len, const std::string& /*addr*/) {
    std::lock_guard<std::mutex> lk(connMutex_);
    if (closed_.load(std::memory_order_acquire)) return;
    if (currentFd_ < 0) return;
    if (addr_.Ports.empty() || addrIndex_ >= addr_.Ports.size()) return;

    // Build target address
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, addr_.IP.c_str(), &sa.sin_addr) != 1) return;
    sa.sin_port = htons(addr_.Ports[addrIndex_]);

    ::sendto(currentFd_, reinterpret_cast<const char*>(buf), static_cast<int>(len), 0,
             reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa));
}

void UdpHopConn::Close() {
    bool expected = false;
    if (!closed_.compare_exchange_strong(expected, true)) return;

    if (prevFd_ >= 0) {
#ifdef _WIN32
        closesocket(prevFd_);
#else
        ::close(prevFd_);
#endif
        prevFd_ = -1;
    }
    if (currentFd_ >= 0) {
#ifdef _WIN32
        closesocket(currentFd_);
#else
        ::close(currentFd_);
#endif
        currentFd_ = -1;
    }

    recvCv_.notify_all();
    if (recvThread_.joinable()) recvThread_.join();
    if (hopThread_.joinable()) hopThread_.join();
}

std::string UdpHopConn::LocalAddr() const {
    std::lock_guard<std::mutex> lk(connMutex_);
    if (currentFd_ < 0) return "";
    struct sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    if (getsockname(currentFd_, reinterpret_cast<struct sockaddr*>(&addr), &len) < 0) return "";
    char ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
}

// ---------------------------------------------------------------------------
// Factory

UdpHopConn* CreateUdpHopConn(const UDPHopAddr& addr, HopIntervalConfig hopInterval) {
    if (addr.Ports.empty()) return nullptr;

    auto* conn = new UdpHopConn();
    conn->addr_ = addr;
    conn->hopInterval_ = hopInterval;
    conn->addrIndex_ = 0; // start with first port

    // Create initial socket
    conn->currentFd_ = createUdpSocket();
    if (conn->currentFd_ < 0) {
        delete conn;
        return nullptr;
    }

    // Start recv and hop threads
    int fd = conn->currentFd_;
    conn->recvThread_ = std::thread([conn, fd] { conn->recvLoop(fd); });
    conn->hopThread_ = std::thread([conn] { conn->hopLoop(); });

    return conn;
}

} // namespace hy2::udphop
