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

// Bidirectional copy between two connections
void bidirectionalCopy(std::shared_ptr<hy2::IByteReaderWriter> a,
                       std::shared_ptr<hy2::IByteReaderWriter> b) {
    std::atomic<bool> done{false};
    auto copier = [&](std::shared_ptr<hy2::IByteReaderWriter> src,
                      std::shared_ptr<hy2::IByteReaderWriter> dst) {
        uint8_t buf[4096];
        while (!done.load(std::memory_order_relaxed)) {
            size_t n = src->Read(buf, sizeof(buf));
            if (n == 0) break;
            try {
                dst->Write(buf, n);
            } catch (...) {
                break;
            }
        }
        done.store(true, std::memory_order_relaxed);
        // Unblock the other direction's blocking Read. Without closing the
        // peer side it stays parked in src->Read() until the remote closes
        // (which never happens for e.g. HTTP keep-alive), so join() below
        // would hang forever. Mirrors core CopyTwoWay's closeQuietly teardown.
        try { a->Close(); } catch (...) {}
        try { b->Close(); } catch (...) {}
    };

    std::thread t1(copier, a, b);
    std::thread t2(copier, b, a);
    t1.join();
    t2.join();
}

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

// Build a SOCKS5 UDP datagram for sending to the client.
// Format: RSV(2)=0 FRAG(1)=0 ATYP ADDR PORT DATA
std::vector<uint8_t> buildSocks5UdpDatagram(const std::string& hostPort,
                                             const uint8_t* data, size_t dataLen) {
    auto addrBytes = buildSocks5Address(hostPort);
    std::vector<uint8_t> pkt;
    pkt.reserve(4 + addrBytes.size() + dataLen);
    pkt.push_back(0x00); // RSV
    pkt.push_back(0x00); // RSV
    pkt.push_back(0x00); // FRAG
    pkt.insert(pkt.end(), addrBytes.begin(), addrBytes.end());
    pkt.insert(pkt.end(), data, data + dataLen);
    return pkt;
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

std::vector<uint8_t> buildSocks5Address(const std::string& hostPort) {
    std::vector<uint8_t> result;
    auto colon = hostPort.rfind(':');
    if (colon == std::string::npos) return result;
    std::string host = hostPort.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(std::atoi(hostPort.c_str() + colon + 1));

    struct in_addr addr4{};
    if (inet_pton(AF_INET, host.c_str(), &addr4) == 1) {
        result.push_back(kAtypIPv4);
        auto* p = reinterpret_cast<uint8_t*>(&addr4);
        result.insert(result.end(), p, p + 4);
    } else if (host.size() > 2 && host[0] == '[' && host.back() == ']') {
        struct in6_addr addr6{};
        std::string ip = host.substr(1, host.size() - 2);
        if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
            result.push_back(kAtypIPv6);
            auto* p = reinterpret_cast<uint8_t*>(&addr6);
            result.insert(result.end(), p, p + 16);
        }
    } else {
        result.push_back(kAtypDomain);
        result.push_back(static_cast<uint8_t>(host.size()));
        result.insert(result.end(), host.begin(), host.end());
    }

    result.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    result.push_back(static_cast<uint8_t>(port & 0xFF));
    return result;
}

// ---------------------------------------------------------------------------
// Socks5Server

void Socks5Server::Serve(std::shared_ptr<server::IConn> listener) {
    // For a real implementation, this would be a TCP accept loop.
    // The IConn interface doesn't support accept(), so this is a placeholder.
    // In practice, the caller would use a real TCP listener and pass
    // accepted connections to dispatch().
    (void)listener;
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
        } else if (atyp == kAtypIPv6) {
            addrLen = 16;
        } else if (atyp == kAtypDomain) {
            uint8_t dlen;
            readExact(*conn, &dlen, 1);
            addrLen = dlen;
        } else {
            sendSimpleReply(*conn, kRepCommandNotSupported);
            conn->Close();
            return;
        }

        addrData.resize(addrLen);
        readExact(*conn, addrData.data(), addrLen);

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

    // Bidirectional copy
    auto connRw = std::static_pointer_cast<hy2::IByteReaderWriter>(conn);
    bidirectionalCopy(connRw, rConn);

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

        while (!done.load(std::memory_order_relaxed)) {
            std::vector<uint8_t> data;
            std::string addr;
            try {
                if (!hyUDP->Receive(data, addr)) break;
            } catch (...) {
                break;
            }

            auto pkt = buildSocks5UdpDatagram(addr, data.data(), data.size());

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
