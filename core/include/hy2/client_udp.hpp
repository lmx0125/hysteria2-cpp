// client_udp.hpp - client-side UDP session manager internals (udp.go port).
// Exposed for testing.
#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>

#include "hy2/client.hpp"
#include "hy2/frag.hpp"
#include "hy2/protocol.hpp"

namespace hy2::client {

constexpr size_t kUdpMessageChanSize = 1024;

// UdpIO mirrors the client-side udpIO interface.
class UdpIO {
public:
    virtual ~UdpIO() = default;
    virtual std::shared_ptr<const proto::UDPMessage> ReceiveMessage() = 0; // throws on closed
    virtual void SendMessage(uint8_t* buf, size_t bufLen, const proto::UDPMessage& msg) = 0;
};

// UdpConn mirrors udpConn in client/udp.go.
class UdpConn : public HyUDPConn {
public:
    uint32_t ID = 0;
    frag::Defragger D;
    std::shared_ptr<Channel<std::shared_ptr<const proto::UDPMessage>>> ReceiveCh;
    UdpIO* IO = nullptr;

    UdpConn(uint32_t id, UdpIO* io);

    bool Receive(std::vector<uint8_t>& data, std::string& addr) override;
    void Send(const uint8_t* data, size_t n, const std::string& addr) override;
    void Close() override;

    bool IsClosed() const { return closed_.load(); }

private:
    friend class ClientUdpSessionManager;
    std::atomic<bool> closed_{false};
};

// ClientUdpSessionManager mirrors udpSessionManager in client/udp.go.
class ClientUdpSessionManager : public std::enable_shared_from_this<ClientUdpSessionManager> {
public:
    // Factory: use this instead of the constructor - it starts the receive
    // loop with proper shared ownership.
    static std::shared_ptr<ClientUdpSessionManager> Create(UdpIO* io);

    ~ClientUdpSessionManager();

    std::shared_ptr<HyUDPConn> NewUDP(); // throws ClosedError when closed
    size_t Count();

private:
    explicit ClientUdpSessionManager(UdpIO* io);

    void run();
    void closeCleanup();
    void feed(std::shared_ptr<const proto::UDPMessage> msg);
    void closeConn(const std::shared_ptr<UdpConn>& conn);

    UdpIO* io_;
    std::shared_mutex mutex_;
    std::map<uint32_t, std::shared_ptr<UdpConn>> m_;
    uint32_t nextID_ = 1;
    bool closed_ = false;
};

} // namespace hy2::client
