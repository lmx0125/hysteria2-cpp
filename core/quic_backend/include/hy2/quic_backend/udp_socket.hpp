#pragma once

#include <atomic>
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

    // ---- TX segmentation (Windows UDP segmentation offload) ----------------
    // Measured on loopback: a plain send of 1350 B costs ~15-16 us, which is
    // 72-80% of this stack's per-packet CPU - the send syscall is the single
    // dominant cost. Windows 10 2004+ can split one send into N datagrams of a
    // fixed size (UDP_SEND_MSG_SIZE), turning N syscalls into one; measured
    // 2.3x lower per-datagram cost at 16 per call.
    //
    // EnableTxSegmentation() asks the stack and reads the value back, so a
    // platform that ignores the option reports failure instead of silently
    // mis-sending. Plain Send()/SendTo() keep working on a segmented socket -
    // verified on this platform, and required because the server shares one
    // socket between batched bulk data and single ACK packets.
    bool EnableTxSegmentation(size_t segLen);
    bool TxSegmentationEnabled() const { return txSegEnabled_; }
    size_t TxSegmentSize() const { return txSegLen_; }

    // One syscall for `totalLen` bytes, sent as totalLen/TxSegmentSize()
    // datagrams of that size, all to `to` (nullptr = connected socket).
    // Returns the number of bytes accepted, or -1. Valid only when
    // segmentation is enabled and totalLen is a non-zero multiple of the
    // segment size; callers must fall back to per-packet sends on -1.
    int SendSegmented(const uint8_t* data, size_t totalLen,
                      const struct sockaddr* to, socklen_t tolen);

    // Drain queued packets (non-blocking). Call after Drive() or on EPOLLOUT.
    // Returns number of bytes still queued (0 = empty).
    size_t DrainTxQueue();

    // Test seam: enqueue a packet exactly the way the WOULDBLOCK branch of
    // Send()/SendTo() does, so the drain contract can be tested without a real
    // kernel backpressure event. It is needed because Windows loopback drops
    // datagrams destined for a full receive queue instead of applying
    // backpressure, so Send() cannot be driven into WSAEWOULDBLOCK there.
    // `to == nullptr` selects the connected-send form, like Send().
    void EnqueueForTest(const uint8_t* data, size_t len,
                        const struct sockaddr* to = nullptr, socklen_t tolen = 0);

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

    // Appends to txQueue_ and raises txQueued_. Caller must hold txMu_.
    // Every enqueue goes through here so the flag cannot be forgotten at one
    // of the four would-block sites (a missed store strands that packet).
    void EnqueueTxLocked(TxPacket&& pkt);

    int fd_ = -1;
    size_t maxDatagramSize_ = 1350;
    // TX segmentation state. Set once by EnableTxSegmentation() and only read
    // afterwards, so no synchronization is needed on the send path.
    bool txSegEnabled_ = false;
    size_t txSegLen_ = 0;
    // Fast-path guard for DrainTxQueue(): true iff txQueue_ is non-empty.
    // Written under txMu_ (release), read without the lock (acquire).
    //
    // Why it exists: the server hands the SAME UdpSocket to every connection,
    // so txMu_ is listener-wide. DrainTxQueue() is called once per Drive() and
    // once per ServerLoop() iteration by each connection, and it used to take
    // that shared lock unconditionally - even when the queue was empty, which
    // is the normal case (a successful sendto never queues anything). With N
    // connections that was N-way contention on one cache line for no work.
    // The flag turns the common case into a single load.
    //
    // Conservative by construction: it may read true when the queue is already
    // empty (one wasted lock acquire), never false when the queue is non-empty
    // (which would strand a packet). Every writer holds txMu_.
    std::atomic<bool> txQueued_{false};
    // Guards txQueue_ and the diagnostic counters. The hot send path only
    // takes this lock when the kernel buffer is full (rare), so concurrent
    // senders (one worker thread per server connection) do not serialize.
    mutable std::mutex txMu_;
    std::deque<TxPacket> txQueue_;
    static constexpr size_t kMaxTxQueue = 256; // max queued packets
    Stats stats_;
};

} // namespace hy2::quic_backend
