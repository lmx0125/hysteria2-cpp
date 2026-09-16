#pragma once

#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
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
#else
  #include <sys/socket.h>
#endif

namespace hy2::quic_backend {

// ---------------------------------------------------------------------------
// UdpSocket: cross-platform UDP socket with non-blocking I/O and tx_queue.
// ---------------------------------------------------------------------------
class UdpSocket {
public:
    UdpSocket();
    ~UdpSocket();

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;
    UdpSocket(UdpSocket&& o) noexcept;
    UdpSocket& operator=(UdpSocket&& o) noexcept;

    bool Bind(const std::string& addr, uint16_t port);
    // localBindAddr (optional): bind the socket's local address before
    // connecting, pinning egress to the interface that owns that address.
    // Ignored when empty or when its address family differs from the peer's.
    bool Connect(const std::string& addr, uint16_t port,
                 const std::string& localBindAddr = std::string());

    // Non-blocking send. Returns bytes sent, or -1 on WOULDBLOCK/error.
    // On WOULDBLOCK, the packet is queued internally.
    int Send(const uint8_t* data, size_t len);
    int SendTo(const uint8_t* data, size_t len,
               const struct sockaddr* to, socklen_t tolen);

    // Drain queued packets (non-blocking). Call after Drive() or on EPOLLOUT.
    // Returns number of bytes still queued (0 = empty).
    size_t DrainTxQueue();

    // Non-blocking recv. Returns bytes received or -1 (EAGAIN/EWOULDBLOCK).
    int Recv(uint8_t* buf, size_t buflen);
    int RecvFrom(uint8_t* buf, size_t buflen,
                 struct sockaddr* from, socklen_t* fromlen);

    void Close();
    int GetFd() const { return fd_; }
    bool IsValid() const { return fd_ >= 0; }

    std::string LocalAddr() const;
    uint16_t LocalPort() const;
    bool LocalSockaddr(struct sockaddr_storage* out, socklen_t* outLen) const;
    bool RemoteSockaddr(struct sockaddr_storage* out, socklen_t* outLen) const;
    std::string RemoteAddr() const;

    void SetMaxDatagramSize(size_t maxSize) { maxDatagramSize_ = maxSize; }
    size_t GetMaxDatagramSize() const { return maxDatagramSize_; }

    // Check if there are queued packets waiting to be sent.
    bool HasQueuedPackets() const;

    // Monitoring counters for performance analysis.
    struct Stats {
        uint64_t txSendSuccess = 0;      // send() returned success
        uint64_t txQueueCount = 0;       // packets queued on WOULDBLOCK
        uint64_t txQueueDrop = 0;        // packets dropped (queue full)
        uint64_t txDrainSuccess = 0;     // queued packets successfully sent
        uint64_t txDrainWouldBlock = 0;  // drain stopped (socket full)
        uint64_t txDrainError = 0;       // drain errors (non-WOULDBLOCK)
        uint64_t rxPackets = 0;          // packets received
        size_t txQueuePeak = 0;          // peak queue depth
    };
    Stats GetStats() const;
    void ResetStats();

    // Read actual kernel socket buffer sizes (after setsockopt).
    struct BufferSizes {
        int sndbuf = 0;
        int rcvbuf = 0;
    };
    BufferSizes GetActualBufferSizes() const;

    // Print stats to stderr for profiling.
    void PrintStats(const char* tag) const;

private:
    struct TxPacket {
        std::vector<uint8_t> data;
        struct sockaddr_storage to{};
        socklen_t tolen = 0;
        bool hasDest = false; // true = sendto, false = send (connected)
    };

    // Try to send one queued packet. Returns true if sent, false if WOULDBLOCK.
    bool DrainOnePacket(TxPacket& pkt);

    int fd_ = -1;
    size_t maxDatagramSize_ = 1350;
    // Guards txQueue_ and the diagnostic counters. The hot send path only
    // takes this lock when the kernel buffer is full (rare), so concurrent
    // senders (one worker thread per server connection) do not serialize.
    mutable std::mutex txMu_;
    std::deque<TxPacket> txQueue_;
    static constexpr size_t kMaxTxQueue = 256; // max queued packets
    Stats stats_;
};

} // namespace hy2::quic_backend
