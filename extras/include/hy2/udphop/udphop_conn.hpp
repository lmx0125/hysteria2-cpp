// udphop_conn.hpp - UDP port hopping connection.
// Rewrite of extras/transport/udphop/conn.go.
// Wraps multiple UDP sockets and hops between server ports at intervals.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "hy2/udphop/udphop.hpp"

namespace hy2::udphop {

// HopIntervalConfig specifies the min/max hop interval.
struct HopIntervalConfig {
    int64_t minNs = 30000000000LL; // 30s default
    int64_t maxNs = 30000000000LL; // 30s default
};

// UdpHopConn wraps multiple UDP sockets and hops between server ports.
// Implements the same interface as net.PacketConn (ReadFrom/WriteTo/Close).
class UdpHopConn {
public:
    // Creates a new UDP hop connection.
    // addr: parsed UDPHopAddr with IP and port list.
    // hopInterval: min/max hop interval.
    ~UdpHopConn();

    // ReadFrom blocks until a packet arrives. Returns the packet data
    // and the server address (always the original addr).
    size_t ReadFrom(uint8_t* buf, size_t len, std::string& addr);

    // WriteTo sends a packet to the current server address.
    void WriteTo(const uint8_t* buf, size_t len, const std::string& addr);

    // Close stops the hop loop and closes all sockets.
    void Close();

    // LocalAddr returns the local address of the current socket.
    std::string LocalAddr() const;

    bool IsClosed() const { return closed_.load(std::memory_order_acquire); }

private:
    friend UdpHopConn* CreateUdpHopConn(const UDPHopAddr& addr,
                                         HopIntervalConfig hopInterval);

    UdpHopConn() = default;

    void recvLoop(int fd);
    void hopLoop();
    int64_t nextHopInterval();
    void hop();

    UDPHopAddr addr_;
    HopIntervalConfig hopInterval_;

    mutable std::mutex connMutex_;
    int prevFd_ = -1;
    int currentFd_ = -1;
    size_t addrIndex_ = 0;

    std::mutex recvMutex_;
    std::condition_variable recvCv_;
    struct RecvPacket {
        std::vector<uint8_t> data;
        std::string from;
    };
    std::deque<RecvPacket> recvQueue_;
    static constexpr size_t kMaxQueueSize = 1024;

    std::atomic<bool> closed_{false};
    std::thread recvThread_;
    std::thread hopThread_;

    mutable std::mt19937 rng_{std::random_device{}()};
};

// Factory function to create a UdpHopConn.
UdpHopConn* CreateUdpHopConn(const UDPHopAddr& addr,
                              HopIntervalConfig hopInterval);

} // namespace hy2::udphop
