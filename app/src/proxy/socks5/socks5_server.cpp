// socks5_server.cpp - SOCKS5 proxy server using Hysteria2 client as outbound.
// Rewrite of app/internal/socks5/server.go.
// Cross-platform: no platform-specific code.
#include "hy2/proxy/socks5/socks5_server.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "hy2/client_udp.hpp"  // UdpConn::kReceiveTimeout
#include "hy2/copy.hpp"
#include "hy2/debug_print.hpp"

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
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

namespace hy2::proxy::socks5 {

namespace {

// Read exactly n bytes from conn
void readExact(server::IConn& conn, uint8_t* buf, size_t n) {
    DBG_LOG("readExact: entering", "n", n);
    size_t got = 0;
    while (got < n) {
        size_t r = conn.Read(buf + got, n - got);
        if (r == 0) {
            DBG_LOG("readExact: connection closed early", "got", got, "expected", n);
            throw std::runtime_error("connection closed");
        }
        got += r;
        DBG_LOG("readExact: partial read", "got", got, "expected", n);
    }
    DBG_LOG("readExact: done", "n", n);
}

// Write bytes to conn
void writeAll(server::IConn& conn, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t remaining = len - off;
        if (remaining > 4096) remaining = 4096;
        conn.Write(data + off, remaining);
        off += remaining;
    }
}

// Send SOCKS5 reply with given code, ATYP, address, and port
void sendReply(server::IConn& conn, uint8_t rep, uint8_t atyp,
               const uint8_t* addr, size_t addrLen,
               const uint8_t* port, size_t portLen) {
    std::vector<uint8_t> reply;
    reply.push_back(0x05); // version
    reply.push_back(rep);  // reply code
    reply.push_back(0x00); // reserved
    reply.push_back(atyp);
    reply.insert(reply.end(), addr, addr + addrLen);
    reply.insert(reply.end(), port, port + portLen);
    writeAll(conn, reply.data(), reply.size());
}

// Send simple reply (no bind address)
void sendSimpleReply(server::IConn& conn, uint8_t rep) {
    uint8_t zeroAddr[4] = {0, 0, 0, 0};
    uint8_t zeroPort[2] = {0, 0};
    sendReply(conn, rep, kAtypIPv4, zeroAddr, 4, zeroPort, 2);
}

// Parse SOCKS5 address from bytes (implementation in header-declared function)

// Parse a SOCKS5 UDP datagram (RFC 1928).
// Returns true on success, filling frag, addrStr ("host:port"), and data.
bool parseSocks5UdpDatagram(const uint8_t* buf, size_t len, uint8_t& frag,
                            std::string& addrStr,
                            const uint8_t*& data, size_t& dataLen) {
    if (len < 4) return false;
    // RSV(2) + FRAG(1) + ATYP(1)
    frag = buf[2];
    uint8_t atyp = buf[3];
    size_t addrFieldLen; // length of the ADDR field (excluding ATYP byte)
    if (atyp == kAtypIPv4) {
        addrFieldLen = 4;
    } else if (atyp == kAtypIPv6) {
        addrFieldLen = 16;
    } else if (atyp == kAtypDomain) {
        if (len < 5) return false;
        addrFieldLen = 1 + buf[4]; // length-prefixed domain
    } else {
        return false;
    }
    size_t headerLen = 4 + addrFieldLen + 2; // RSV FRAG ATYP ADDR PORT
    if (len < headerLen) return false;
    // parseSocks5Address for domains expects addr pointing to the length byte,
    // with addrLen = domainLen + 1 (it does addr+1, addrLen-1 internally).
    // For IPv4/IPv6: addr = buf+4, addrLen = 4 or 16
    size_t parseAddrLen;
    const uint8_t* parseAddrPtr;
    if (atyp == kAtypDomain) {
        parseAddrPtr = buf + 4; // points to length byte (ATYP+length combined)
        parseAddrLen = static_cast<size_t>(buf[4]) + 1; // length byte + domain
    } else {
        parseAddrPtr = buf + 4;
        parseAddrLen = addrFieldLen;
    }
    addrStr = parseSocks5Address(atyp, parseAddrPtr, parseAddrLen, buf + headerLen - 2);
    data = buf + headerLen;
    dataLen = len - headerLen;
    return true;
}

// Append the SOCKS5 address field (ATYP ADDR PORT) for hostPort into `out`.
// hostPort is "ip:port" / "[ipv6]:port" / "domain:port"; a string without a
// colon contributes nothing, exactly as buildSocks5Address() always has.
void buildSocks5AddressInto(std::vector<uint8_t>& out, const std::string& hostPort) {
    auto colon = hostPort.rfind(':');
    if (colon == std::string::npos) return;
    std::string host = hostPort.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(hostPort.c_str() + colon + 1));

    struct in_addr addr4{};
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) {
        out.push_back(kAtypIPv4);
        auto* p = reinterpret_cast<uint8_t*>(&addr4);
        out.insert(out.end(), p, p + 4);
    } else if (host.size() > 2 && host[0] == '[' && host.back() == ']') {
        struct in6_addr addr6{};
        std::string ip = host.substr(1, host.size() - 2);
        if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
            out.push_back(kAtypIPv6);
            auto* p = reinterpret_cast<uint8_t*>(&addr6);
            out.insert(out.end(), p, p + 16);
        }
    } else {
        out.push_back(kAtypDomain);
        out.push_back(static_cast<uint8_t>(host.size()));
        out.insert(out.end(), host.begin(), host.end());
    }

    out.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(port & 0xFF));
}

// Build a SOCKS5 UDP datagram for sending to the client, into `out` (cleared
// first, capacity kept). The relay sends one of these per received datagram,
// so returning a fresh vector - plus a second temporary one for the address -
// meant several allocations per packet for a buffer that is always the same
// shape. The address lands directly in `out` and the 3-byte header is inserted
// in front of it, which is cheaper than building the two separately and
// copying both in.
// Format: RSV(2)=0 FRAG(1)=0 ATYP ADDR PORT DATA
void buildSocks5UdpDatagramInto(std::vector<uint8_t>& out, const std::string& hostPort,
                                const uint8_t* data, size_t dataLen) {
    out.clear();
    buildSocks5AddressInto(out, hostPort);
    out.reserve(3 + out.size() + dataLen);
    out.insert(out.begin(), 3, 0x00);  // RSV RSV FRAG
    out.insert(out.end(), data, data + dataLen);
}

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSock = INVALID_SOCKET;
inline void closeSock(socket_t s) { closesocket(s); }
#else
using socket_t = int;
constexpr socket_t kInvalidSock = -1;
inline void closeSock(socket_t s) { ::close(s); }
#endif

// Nagle holds a small write until the previous one is acknowledged, and on
// Windows the delayed-ACK timer is 200 ms - an interactive request/response
// stream through the proxy stutters by that much. The relay writes whole
// buffers, so there is nothing worth coalescing here.
inline void setTcpNoDelay(socket_t s) {
    int on = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&on), sizeof(on));
}

// SocketConn - wraps a raw TCP socket as hy2::server::IConn
class SocketConn : public server::IConn {
public:
    explicit SocketConn(socket_t fd) : fd_(fd) {}
    ~SocketConn() override { Close(); }

    SocketConn(const SocketConn&) = delete;
    SocketConn& operator=(const SocketConn&) = delete;

    size_t Read(uint8_t* buf, size_t n) override {
        if (fd_ == kInvalidSock) return 0;
#ifdef _WIN32
        int r = recv(fd_, reinterpret_cast<char*>(buf), static_cast<int>(n), 0);
#else
        ssize_t r = ::recv(fd_, buf, n, 0);
#endif
        if (r <= 0) return 0;
        return static_cast<size_t>(r);
    }

    void Write(const uint8_t* buf, size_t n) override {
        if (fd_ == kInvalidSock) throw std::runtime_error("write on closed socket");
        size_t off = 0;
        while (off < n) {
#ifdef _WIN32
            int sent = send(fd_, reinterpret_cast<const char*>(buf + off),
                            static_cast<int>(n - off), 0);
#else
            ssize_t sent = ::send(fd_, buf + off, n - off, 0);
#endif
            if (sent <= 0) throw std::runtime_error("write failed");
            off += static_cast<size_t>(sent);
        }
    }

    void Close() override {
        if (fd_ != kInvalidSock) {
            closeSock(fd_);
            fd_ = kInvalidSock;
        }
    }

private:
    socket_t fd_;
};

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public functions (declared in header)

std::string parseSocks5Address(uint8_t atyp, const uint8_t* addr, size_t addrLen,
                                const uint8_t* port) {
    std::string host;
    if (atyp == kAtypIPv4) {
        if (addrLen < 4) return "";
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, addr, ip, sizeof(ip));
        host = ip;
    } else if (atyp == kAtypIPv6) {
        if (addrLen < 16) return "";
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, addr, ip, sizeof(ip));
        host = std::string("[") + ip + "]";
    } else if (atyp == kAtypDomain) {
        if (addrLen < 1) return "";
        host = std::string(reinterpret_cast<const char*>(addr + 1), addrLen - 1);
    } else {
        return "";
    }
    uint16_t p = (static_cast<uint16_t>(port[0]) << 8) | port[1];
    return host + ":" + std::to_string(p);
}

// Kept for the module tests (Socks5_BuildSocks5Address_*); the UDP relay builds
// the same bytes straight into its reusable datagram buffer instead.
std::vector<uint8_t> buildSocks5Address(const std::string& hostPort) {
    std::vector<uint8_t> result;
    buildSocks5AddressInto(result, hostPort);
    return result;
}

// ---------------------------------------------------------------------------
// TcpListener

TcpListener::~TcpListener() { Close(); }

bool TcpListener::Listen(uint16_t port) {
#ifdef _WIN32
    fd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_ == kInvalid) return false;
    int yes = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&yes), sizeof(yes));
#else
    fd_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd_ < 0) return false;
    int yes = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        closeSock(fd_);
        fd_ = kInvalid;
        return false;
    }
    if (::listen(fd_, SOMAXCONN) < 0) {
        closeSock(fd_);
        fd_ = kInvalid;
        return false;
    }
    return true;
}

std::shared_ptr<server::IConn> TcpListener::Accept() {
    if (fd_ == kInvalid) return nullptr;
#ifdef _WIN32
    SOCKET client = ::accept(fd_, nullptr, nullptr);
    if (client == INVALID_SOCKET) return nullptr;
#else
    int client = ::accept(fd_, nullptr, nullptr);
    if (client < 0) return nullptr;
#endif
    setTcpNoDelay(client);
    return std::make_shared<SocketConn>(client);
}

void TcpListener::Close() {
    if (fd_ != kInvalid) {
        closeSock(fd_);
        fd_ = kInvalid;
    }
}

// ---------------------------------------------------------------------------
// Socks5Server

void Socks5Server::Serve(std::shared_ptr<server::IConn> listener) {
    // Serve from an already-accepted connection (single connection mode).
    // For multi-connection mode, use ServeOnPort().
    dispatch(listener);
}

bool Socks5Server::ServeOnPort(uint16_t port, std::atomic<bool>& stop) {
    TcpListener listener;
    if (!listener.Listen(port)) {
        return false;
    }

    while (!stop.load(std::memory_order_relaxed)) {
        auto conn = listener.Accept();
        if (!conn) break; // listener closed
        TrackConn(conn);
        // Keep the server (and its session counters) alive for the detached
        // session when the host owns it through a shared_ptr. Hosts that
        // create the server otherwise (e.g. a stack/unique_ptr instance in
        // tests) must keep it alive themselves.
        std::shared_ptr<Socks5Server> self = weak_from_this().lock();
        Socks5Server* owner = self ? self.get() : this;
        std::thread([self, owner, conn]() {
            owner->SessionBegin();
            struct SessionScope {
                Socks5Server* s;
                ~SessionScope() { s->SessionEnd(); }
            } scope{owner};
            try {
                owner->dispatch(conn);
            } catch (...) {
                try { conn->Close(); } catch (...) {}
            }
        }).detach();
    }

    listener.Close();
    return true;
}

bool Socks5Server::WaitForSessions(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(sessionMu_);
    return sessionCv_.wait_for(lk, timeout, [this] {
        return activeSessions_.load(std::memory_order_relaxed) == 0;
    });
}

void Socks5Server::TrackConn(const std::shared_ptr<server::IConn>& conn) {
    std::lock_guard<std::mutex> lk(connMu_);
    conns_.erase(std::remove_if(conns_.begin(), conns_.end(),
                                [](const std::weak_ptr<server::IConn>& w) {
                                    return w.expired();
                                }),
                 conns_.end());
    conns_.push_back(conn);
}

void Socks5Server::CloseSessions() {
    std::vector<std::shared_ptr<server::IConn>> live;
    {
        std::lock_guard<std::mutex> lk(connMu_);
        for (auto& w : conns_) {
            if (auto c = w.lock()) live.push_back(c);
        }
        conns_.clear();
    }
    for (auto& c : live) {
        try { c->Close(); } catch (...) {}
    }
}

void Socks5Server::dispatch(std::shared_ptr<server::IConn> conn) {
    try {
        if (!negotiate(*conn)) {
            conn->Close();
            return;
        }

        // Read SOCKS5 request: VER CMD RSV ATYP DST.ADDR DST.PORT
        uint8_t reqHeader[4];
        readExact(*conn, reqHeader, 4);
        if (reqHeader[0] != 0x05) {
            conn->Close();
            return;
        }
        uint8_t cmd = reqHeader[1];
        uint8_t atyp = reqHeader[3];

        // Read destination address
        std::vector<uint8_t> addrData;
        size_t addrLen = 0;
        if (atyp == kAtypIPv4) {
            addrLen = 4;
            addrData.resize(addrLen);
            readExact(*conn, addrData.data(), addrLen);
        } else if (atyp == kAtypIPv6) {
            addrLen = 16;
            addrData.resize(addrLen);
            readExact(*conn, addrData.data(), addrLen);
        } else if (atyp == kAtypDomain) {
            uint8_t dlen;
            readExact(*conn, &dlen, 1);
            // parseSocks5Address expects the domain field as length byte + host,
            // so keep the length byte at the front of the buffer.
            addrLen = static_cast<size_t>(dlen) + 1;
            addrData.resize(addrLen);
            addrData[0] = dlen;
            readExact(*conn, addrData.data() + 1, dlen);
        } else {
            sendSimpleReply(*conn, kRepCommandNotSupported);
            conn->Close();
            return;
        }

        uint8_t portBytes[2];
        readExact(*conn, portBytes, 2);

        std::string targetAddr = parseSocks5Address(atyp, addrData.data(), addrLen, portBytes);

        switch (cmd) {
        case kCmdConnect:
            handleTCP(conn, targetAddr);
            break;
        case kCmdUDP:
            if (DisableUDP) {
                sendSimpleReply(*conn, kRepCommandNotSupported);
                conn->Close();
            } else {
                handleUDP(conn, targetAddr);
            }
            break;
        default:
            sendSimpleReply(*conn, kRepCommandNotSupported);
            conn->Close();
            break;
        }
    } catch (...) {
        try { conn->Close(); } catch (...) {}
    }
}

bool Socks5Server::negotiate(server::IConn& conn) {
    // Read version + nMethods
    uint8_t header[2];
    readExact(conn, header, 2);
    if (header[0] != 0x05) return false;
    uint8_t nMethods = header[1];

    // Read methods
    std::vector<uint8_t> methods(nMethods);
    readExact(conn, methods.data(), nMethods);

    // Determine server method
    uint8_t serverMethod = AuthFunc ? kMethodUsernamePassword : kMethodNone;

    // Check if client supports our method
    bool supported = false;
    for (uint8_t m : methods) {
        if (m == serverMethod) {
            supported = true;
            break;
        }
    }

    if (!supported) {
        uint8_t reply[2] = {0x05, kMethodUnsupportAll};
        writeAll(conn, reply, 2);
        return false;
    }

    // Send chosen method
    uint8_t methodReply[2] = {0x05, serverMethod};
    writeAll(conn, methodReply, 2);

    // If username/password auth, authenticate
    if (serverMethod == kMethodUsernamePassword) {
        uint8_t authHeader[2];
        readExact(conn, authHeader, 2);
        if (authHeader[0] != 0x01) return false; // version must be 1

        uint8_t ulen = authHeader[1];
        std::vector<uint8_t> udata(ulen);
        readExact(conn, udata.data(), ulen);

        uint8_t plen;
        readExact(conn, &plen, 1);
        std::vector<uint8_t> pdata(plen);
        readExact(conn, pdata.data(), plen);

        std::string username(reinterpret_cast<char*>(udata.data()), ulen);
        std::string password(reinterpret_cast<char*>(pdata.data()), plen);

        bool ok = AuthFunc(username, password);
        uint8_t authReply[2] = {0x01, ok ? kUserPassStatusSuccess : kUserPassStatusFailure};
        writeAll(conn, authReply, 2);

        if (!ok) return false;
    }

    return true;
}

void Socks5Server::handleTCP(std::shared_ptr<server::IConn> conn,
                              const std::string& targetAddr) {
    // Log
    if (EventLogger) {
        EventLogger->TCPRequest("", targetAddr);
    }

    // Dial via Hysteria2 client
    std::shared_ptr<hy2::IByteReaderWriter> rConn;
    try {
        rConn = HyClient->TCP(targetAddr);
    } catch (...) {
        sendSimpleReply(*conn, kRepHostUnreachable);
        if (EventLogger) {
            EventLogger->TCPError("", targetAddr, "dial failed");
        }
        return;
    }

    // Send success reply
    sendSimpleReply(*conn, kRepSuccess);

    // Bidirectional copy using core CopyTwoWay (TLS buffer pool, 32KB buffers)
    auto connRw = std::static_pointer_cast<hy2::IByteReaderWriter>(conn);
    server::CopyTwoWay(connRw, rConn);

    if (EventLogger) {
        EventLogger->TCPError("", targetAddr, "");
    }
}

void Socks5Server::handleUDP(std::shared_ptr<server::IConn> conn,
                              const std::string& targetAddr) {
    if (EventLogger) {
        EventLogger->UDPRequest("");
    }

    // 1. Bind local UDP socket
    socket_t udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSock == kInvalidSock) {
        sendSimpleReply(*conn, kRepServerFailure);
        if (EventLogger) EventLogger->UDPError("", "UDP socket create failed");
        return;
    }

    struct sockaddr_in bindAddr{};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bindAddr.sin_port = 0; // kernel picks a free port
    if (::bind(udpSock, reinterpret_cast<struct sockaddr*>(&bindAddr),
               sizeof(bindAddr)) < 0) {
        closeSock(udpSock);
        sendSimpleReply(*conn, kRepServerFailure);
        if (EventLogger) EventLogger->UDPError("", "UDP bind failed");
        return;
    }

    // Read back the assigned port
    struct sockaddr_in localAddr{};
    socklen_t addrLen = sizeof(localAddr);
    getsockname(udpSock, reinterpret_cast<struct sockaddr*>(&localAddr), &addrLen);

    // 2. Create Hy2 UDP session
    std::shared_ptr<client::HyUDPConn> hyUDP;
    try {
        hyUDP = HyClient->UDP();
    } catch (...) {
        closeSock(udpSock);
        sendSimpleReply(*conn, kRepServerFailure);
        if (EventLogger) EventLogger->UDPError("", "Hy2 UDP session failed");
        return;
    }

    // 3. Send SOCKS5 success reply with bind address
    {
        uint8_t addrBytes[4];
        std::memcpy(addrBytes, &localAddr.sin_addr, 4);
        uint8_t portBytes[2] = {
            static_cast<uint8_t>((ntohs(localAddr.sin_port) >> 8) & 0xFF),
            static_cast<uint8_t>(ntohs(localAddr.sin_port) & 0xFF)
        };
        sendReply(*conn, kRepSuccess, kAtypIPv4, addrBytes, 4, portBytes, 2);
    }

    // 4. Start bidirectional UDP relay
    std::atomic<bool> done{false};
    std::mutex clientAddrMu;
    struct sockaddr_in relayClientAddr{};
    bool relayClientAddrReady = false;
    std::condition_variable clientAddrCv;

    // Local → Remote: recvfrom(udpSock), strip SOCKS5 header, hyUDP->Send()
    std::thread localToRemote([this, udpSock, &hyUDP, &done,
                               &clientAddrMu, &relayClientAddr, &relayClientAddrReady,
                               &clientAddrCv] {
        std::vector<uint8_t> buf(kUdpBufferSize);
        struct sockaddr_in clientSockAddr{};
        socklen_t clientAddrLen = sizeof(clientSockAddr);

        while (!done.load(std::memory_order_relaxed)) {
            clientAddrLen = sizeof(clientSockAddr);
            int n = recvfrom(udpSock, reinterpret_cast<char*>(buf.data()),
                             static_cast<int>(buf.size()), 0,
                             reinterpret_cast<struct sockaddr*>(&clientSockAddr),
                             &clientAddrLen);
            if (n <= 0) break;

            // First packet determines client address (Go behavior)
            {
                std::lock_guard<std::mutex> lk(clientAddrMu);
                if (!relayClientAddrReady) {
                    relayClientAddr = clientSockAddr;
                    relayClientAddrReady = true;
                    clientAddrCv.notify_one();
                } else if (clientSockAddr.sin_addr.s_addr != relayClientAddr.sin_addr.s_addr ||
                           clientSockAddr.sin_port != relayClientAddr.sin_port) {
                    continue; // Not our client, ignore
                }
            }

            uint8_t frag = 0;
            std::string addrStr;
            const uint8_t* data = nullptr;
            size_t dataLen = 0;
            if (!parseSocks5UdpDatagram(buf.data(), static_cast<size_t>(n),
                                         frag, addrStr, data, dataLen)) {
                continue;
            }
            if (frag != 0) continue; // No SOCKS5 UDP fragmentation support

            try {
                hyUDP->Send(data, dataLen, addrStr);
            } catch (...) {
                break;
            }
        }
    });

    // Remote → Local: hyUDP->Receive(), build SOCKS5 datagram, sendto(udpSock)
    std::thread remoteToLocal([udpSock, &hyUDP, &done,
                               &clientAddrMu, &relayClientAddr, &relayClientAddrReady,
                               &clientAddrCv] {
        // Wait for first local→remote packet to learn client address
        {
            std::unique_lock<std::mutex> lk(clientAddrMu);
            clientAddrCv.wait(lk, [&] { return relayClientAddrReady || done.load(); });
        }

        // Reused for every reply datagram (see buildSocks5UdpDatagramInto).
        std::vector<uint8_t> pkt;
        while (!done.load(std::memory_order_relaxed)) {
            std::vector<uint8_t> data;
            std::string addr;
            try {
                // Receive() returns false for a quiet poll as well as for a
                // closed session, and this loop used to treat both as EOF -
                // so any UDP flow with a >100 ms gap between replies (a DNS
                // lookup, a QUIC handshake, a game keepalive) had its relay
                // torn down mid-session. Ask which one it was instead.
                const auto r = hyUDP->ReceivePacket(data, addr,
                                                    hyUDP->ReceivePollTimeout());
                if (r == client::UdpRecvResult::kClosed) break;
                if (r == client::UdpRecvResult::kTimeout) continue;
            } catch (...) {
                break;
            }

            buildSocks5UdpDatagramInto(pkt, addr, data.data(), data.size());

            // Send back to the client
            std::lock_guard<std::mutex> lk(clientAddrMu);
            if (relayClientAddrReady) {
                sendto(udpSock, reinterpret_cast<const char*>(pkt.data()),
                       static_cast<int>(pkt.size()), 0,
                       reinterpret_cast<struct sockaddr*>(&relayClientAddr),
                       sizeof(relayClientAddr));
            }
        }
    });

    // 5. Block until TCP control connection closes or relay exits
    //    (mirrors Go: io.Copy(io.Discard, conn))
    try {
        uint8_t drainBuf[256];
        while (conn->Read(drainBuf, sizeof(drainBuf)) > 0) {}
    } catch (...) {}

    // 6. Cleanup: signal threads, close resources, join
    done.store(true, std::memory_order_relaxed);
    closeSock(udpSock);
    try { hyUDP->Close(); } catch (...) {}

    if (localToRemote.joinable()) localToRemote.join();
    if (remoteToLocal.joinable()) remoteToLocal.join();

    if (EventLogger) {
        EventLogger->UDPError("", "");
    }
}

} // namespace hy2::proxy::socks5
