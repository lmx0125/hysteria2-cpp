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
    virtual std::shared_ptr<proto::UDPMessage> ReceiveMessage() = 0; // throws on closed
    virtual void SendMessage(uint8_t* buf, size_t bufLen, const proto::UDPMessage& msg) = 0;
};

// UdpConn mirrors udpConn in client/udp.go.
class UdpConn : public HyUDPConn {
public:
    uint32_t ID = 0;
    frag::Defragger D;
    std::shared_ptr<Channel<std::shared_ptr<proto::UDPMessage>>> ReceiveCh;
    // Shared ownership: an outstanding relay connection must keep its IO (and
    // through it the QUIC connection) alive. With a raw pointer, destroying
    // the Client while sessions were still in use left Send()/Receive()
    // writing through a dangling UdpIO* (crash: 0xC0000005 in UdpConn::Send).
    std::shared_ptr<UdpIO> IO;

    UdpConn(uint32_t id, std::shared_ptr<UdpIO> io);

    bool Receive(std::vector<uint8_t>& data, std::string& addr) override;
    UdpRecvResult ReceivePacket(std::vector<uint8_t>& data, std::string& addr,
                                Duration timeout) override;
    Duration ReceivePollTimeout() const override {
        return Duration::FromMillis(kReceiveTimeout.count());
    }
    void Send(const uint8_t* data, size_t n, const std::string& addr) override;
    void Close() override;

    bool IsClosed() const { return closed_.load(); }

    // How long Receive() waits before reporting nothing. Exposed for tests:
    // the relay loops under test must not have to run for a real second.
    static constexpr auto kReceiveTimeout = std::chrono::milliseconds(100);

private:
    friend class ClientUdpSessionManager;
    std::atomic<bool> closed_{false};
};

// ClientUdpSessionManager mirrors udpSessionManager in client/udp.go.
class ClientUdpSessionManager : public std::enable_shared_from_this<ClientUdpSessionManager> {
public:
    // Factory: use this instead of the constructor - it starts the receive
    // loop with proper shared ownership.
    static std::shared_ptr<ClientUdpSessionManager> Create(std::shared_ptr<UdpIO> io);

    ~ClientUdpSessionManager();

    std::shared_ptr<HyUDPConn> NewUDP(); // throws ClosedError when closed
    size_t Count();

private:
    explicit ClientUdpSessionManager(std::shared_ptr<UdpIO> io);

    void run();
    void closeCleanup();
    void feed(std::shared_ptr<proto::UDPMessage> msg);
    void closeConn(const std::shared_ptr<UdpConn>& conn);

    std::shared_ptr<UdpIO> io_;
    std::shared_mutex mutex_;
    std::map<uint32_t, std::shared_ptr<UdpConn>> m_;
    uint32_t nextID_ = 1;
    bool closed_ = false;
};

} // namespace hy2::client
