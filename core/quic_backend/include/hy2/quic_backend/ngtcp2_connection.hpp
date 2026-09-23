#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef int socklen_t;
#else
  #include <sys/socket.h>
#endif

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/ssl.h>

#include "hy2/quic.hpp"
#include "hy2/quic_config.hpp"
#include "hy2/quic_backend/udp_socket.hpp"

namespace hy2::quic_backend {

class Ngtcp2Stream;
class Ngtcp2Listener;

// ---------------------------------------------------------------------------
// RTTStats: concrete RTTStatsProvider backed by ngtcp2's internal RTT tracking.
// ---------------------------------------------------------------------------
class RttStats : public cc::RTTStatsProvider {
public:
    Duration MinRTT() const override;
    Duration LatestRTT() const override;
    Duration SmoothedRTT() const override;
    Duration MeanDeviation() const override;

    // Called from ngtcp2_conn_get_rtt() results.
    void Update(Duration latestRTT);

private:
    Duration minRTT_{};
    Duration latestRTT_{};
    Duration smoothedRTT_{};
    Duration meanDeviation_{};
    bool hasSample_ = false;
};

// ---------------------------------------------------------------------------
// Ngtcp2Connection: wraps ngtcp2_conn + OpenSSL QUIC-TLS, implements
// IQuicConnection so session/protocol code can use it transparently.
//
// Lifetime: created by Ngtcp2Listener::Accept (server) or
// Ngtcp2Connection::Connect (client). Destroying this object tears down
// the QUIC connection (send CONNECTION_CLOSE, free resources).
// ---------------------------------------------------------------------------
class Ngtcp2Connection : public IQuicConnection,
                         public std::enable_shared_from_this<Ngtcp2Connection> {
public:
    // ---- Client-side connect ----
    struct ClientParams {
        std::string remoteAddr;       // "host:port"
        std::string serverName;       // SNI
        // Optional local address to bind the QUIC socket to (pins egress to
        // the interface owning it; see QuicConfig::LocalBindAddr).
        std::string localBindAddr;
        uint16_t remotePort = 0;
        // TLS
        SSL_CTX* sslCtx = nullptr;
        bool insecureSkipVerify = false;
        std::vector<std::string> rootCAsPEM;
        // QUIC config
        QuicConfig quicCfg;
        // Auth (sent via H3 round trip later)
        std::string authToken;
    };

    static std::shared_ptr<Ngtcp2Connection> Connect(const ClientParams& params,
                                                      cc::CongestionControl* ccOverride = nullptr);

    // ---- Server-side factory (called by Ngtcp2Listener) ----
    struct ServerInitParams {
        Ngtcp2Listener* listener = nullptr;
        SSL_CTX* sslCtx = nullptr;
        const ngtcp2_pkt_hd* hd = nullptr;          // client Initial header
        const struct sockaddr* remoteAddr = nullptr;
        socklen_t remoteAddrLen = 0;
        const struct sockaddr* localAddr = nullptr;
        socklen_t localAddrLen = 0;
        QuicConfig quicCfg;
        bool datagramEnabled = false;
    };
    static std::shared_ptr<Ngtcp2Connection> CreateServer(const ServerInitParams& p);

    // ---- Server-side (constructed by listener after handshake) ----
    // Not typically called directly; use Ngtcp2Listener::Accept.

    ~Ngtcp2Connection() override;

    // IQuicConnection
    std::shared_ptr<IQuicStream> OpenStream() override;
    std::shared_ptr<IQuicStream> OpenUniStream() override;
    std::shared_ptr<IQuicStream> AcceptUniStream() override;
    std::shared_ptr<IQuicStream> AcceptStream() override;
    // Timed accept: returns nullptr after timeoutMs if no stream arrives.
    std::shared_ptr<IQuicStream> AcceptStreamFor(int timeoutMs);
    void SendDatagram(const uint8_t* p, size_t n) override;
    std::vector<uint8_t> ReceiveDatagram() override;
    void CloseWithError(uint64_t errorCode, const std::string& reason) override;
    std::string LocalAddr() const override;
    std::string RemoteAddr() const override;

    // Returns flow-control credit for bytes the application consumed from a
    // stream (called by Ngtcp2Stream::Read). Consumption - not arrival -
    // drives the receive window, so a slow reader bounds how much the peer
    // may send and Ngtcp2Stream::readBuf_ stays bounded. Safe to call with a
    // closed/unknown stream id (ngtcp2 ignores it); wakes the IO loop so the
    // MAX_STREAM_DATA/MAX_DATA update is emitted promptly.
    void ExtendReadCredit(int64_t stream_id, uint64_t credit);

    // Congestion control integration
    void SetCongestionControl(std::shared_ptr<cc::CongestionControl> cc) override;

    // Called by event loop when UDP datagram arrives.
    void OnUdpRecv(const uint8_t* data, size_t len,
                   const struct sockaddr* addr, socklen_t addrlen);

    // ---- Server-side per-connection worker loop ----
    // Ngtcp2Listener::RecvLoop only receives datagrams and hands them to the
    // owning connection via EnqueueRx(); ServerLoop() then performs
    // read_pkt/Drive()/timers on this connection's own thread. Without this,
    // every server connection's crypto ran on the single listener thread,
    // capping total server throughput at roughly one CPU core
    // (~250-300 Mbps on a laptop).
    void EnqueueRx(const uint8_t* data, size_t len);
    void StartServerLoop();
    void StopServerLoop();
    // Batch variant used by the server worker loop: one op-lock acquisition
    // for a whole batch of datagrams instead of one per packet.
    void OnUdpRecvBatch(const std::deque<std::vector<uint8_t>>& batch);

    // Immediately stops this connection without sending CONNECTION_CLOSE.
    // Used when a stale connection is replaced on a reused UDP 4-tuple so
    // its worker loop stops emitting packets towards the new client.
    void Abort();

    // Clears the non-owning references into the owning Ngtcp2Listener (wake
    // pipe write end, shared server socket, listener back pointer). Called by
    // Ngtcp2Listener::Close() before the listener is torn down: a server
    // connection can outlive it (the H3 handler and its detached stream
    // workers hold it), and Stream::Write() would otherwise send through the
    // freed wake socket handle.
    void DetachFromListener();

    // Called by event loop on timeout.
    void OnTimeout();

    // Returns the time the next timer should fire.
        std::chrono::steady_clock::time_point GetExpiry() const;
    // Get the underlying UDP socket fd for select/poll.
    int GetSocketFd() const;
    // Called by EventLoop when the socket has data ready to read.
    void OnUdpRecvReady();

    // True when ngtcp2's loss/ack timers are due RIGHT NOW.
    bool TimerOverdue() const {
        if (!conn_ || closed_) return false;
        ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry2(conn_);
        // UINT64_MAX = no timer armed (ngtcp2 convention).
        if (expiry == UINT64_MAX) return false;
        return expiry <=
               static_cast<ngtcp2_tstamp>(
                   std::chrono::duration_cast<std::chrono::nanoseconds>(
                       std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // Wake the event-loop thread (listener's RecvLoop or client's InternalLoop)
    // so it flushes pending write data immediately. Called by Stream::Write().
    // Unconditional variant: used by close/stop paths that must always wake
    // the loop regardless of the tx-pending flag state.
    void WakeUp();
    // Edge-triggered wake for stream data writes: only writes the pipe when
    // the tx-pending flag transitions false->true. Repeated Write() calls
    // while the IO thread is already driving (or already owed work) skip the
    // syscall entirely.
    void WakeUpOnData();

    // Set the wake pipe write-end pointer (called by Ngtcp2Listener::RegisterConn).
#ifdef _WIN32
    void SetWakeFd(SOCKET* fd) { wakeWrite_ = fd; }
#else
    void SetWakeFd(int* fd) { wakeWrite_ = fd; }
#endif

    // Drive the ngtcp2 state machine (send pending packets via UDP).
    void Drive();

    // Client-side internal receive/timer loop. Keeps the connection alive
    // via shared_from_this while running.
    void StartInternalLoop();
    void StopInternalLoop();

    // Set callback for accepting incoming streams (server-side).
    void SetStreamAcceptCallback(std::function<void(std::shared_ptr<IQuicStream>)> cb);

    // Get the local addresses the socket is bound to.
    std::string LocalHost() const;
    uint16_t LocalPort() const;

    // Check if handshake is complete.
    bool IsHandshakeComplete() const { return handshakeComplete_.load(); }

    // True once the connection reached a terminal state (idle close, peer
    // CONNECTION_CLOSE/draining, or explicit local close). Overrides
    // IQuicConnection so callers holding only the interface can notice a
    // connection that died on its own.
    bool IsClosed() const override { return closed_.load(); }

    // IQuicConnection: backend-neutral counters for the rate controller.
    QuicStatsSnapshot GetStatsSnapshot() const override;

    // Get ngtcp2 connection ID for logging.
    uint64_t GetConnectionId() const;

    // QUIC-level performance stats for benchmarking.
    struct QuicStats {
        uint64_t bytesSent = 0;
        uint64_t bytesReceived = 0;
        uint64_t packetsSent = 0;
        uint64_t packetsReceived = 0;
        uint64_t packetsLost = 0;
        uint64_t packetsRetransmitted = 0;
        uint64_t streamsOpen = 0;
        uint64_t streamsActive = 0;
        double smoothedRttUs = 0;
        uint64_t cwnd = 0;
        uint64_t bytesInFlight = 0;
        uint64_t maxTxUdpPayloadSize = 0;
    };
    QuicStats GetQuicStats() const;

    // Print full stats to stderr for profiling.
    void PrintStats() const;

    // HY2_DIAG stall helper: once per second prints the event-loop counters
    // and the state of every stream (buffered bytes, offsets, which stream
    // mutex is held). One run then shows exactly where a transfer stalled.
    void ConnHeartbeat(const char* role);

    // Socket TX stats for download diagnostics.
    struct SocketTxStats {
        uint64_t sendSuccess = 0;
        uint64_t queueCount = 0;
        uint64_t queueDrop = 0;
        uint64_t drainSuccess = 0;
        uint64_t drainWouldBlock = 0;
    };
    SocketTxStats GetSocketTxStats() const;

    // Raw ngtcp2 handle (used by streams to submit stream data).
    ngtcp2_conn* RawConn() { return conn_; }

    // The client-chosen source CID of this connection (server side only:
    // equals dcid_ which we set from the client Initial's SCID).
    const ngtcp2_cid& ClientScid() const { return dcid_; }

    // The server-chosen source CID: a client Initial for THIS connection
    // carries it as its destination CID. Used by the listener to tell a
    // retransmitted Initial apart from a brand-new connection (the hy2
    // client uses zero-length SCIDs, so SCIDs cannot be compared).
    const ngtcp2_cid& ServerScid() const { return scid_; }

    // The DCID carried by the client's very FIRST Initial: a value the CLIENT
    // picked, before it could possibly know our SCID. Every packet of the same
    // initial flight still carries it - QUIC splits the ClientHello across
    // several Initials, and a retransmission reuses the same one - so while the
    // client has not yet seen our reply this is the ONLY thing identifying the
    // connection. Comparing against ServerScid() alone made the listener treat
    // each of those as a brand-new connection (see ngtcp2_listener.cpp).
    const ngtcp2_cid& OriginalDcid() const {
        return transportParams_.original_dcid;
    }

    // Serializes ALL ngtcp2 entry points (Drive/OnUdpRecv/OnTimeout +
    // app-thread OpenStream/SendDatagram/CloseWithError). ngtcp2 requires
    // monotonically increasing timestamps per connection, so these must
    // never run concurrently. The IO-loop entry points all live on one
    // thread, so this mutex is uncontended except during brief app-thread
    // ops (datagram TX / stream open).
    void BeginOpBlocking() { opMu_.lock(); }
    void EndOp() { opMu_.unlock(); }

    // Mark that the QUIC state machine owes the socket some packets (stream
    // data, ACKs, PTO retransmits). Set by WakeUp/OnUdpRecv/OnTimeout;
    // consumed by the IO loop before calling Drive() so connections with no
    // work are never driven (server: O(conns) drive filter).
    void MarkTxPending() { txPending_.store(true, std::memory_order_relaxed); }
    // Returns true when the flag transitioned false->true (the caller must
    // wake the IO thread); false when it was already set (wake not needed).
    bool MarkTxPendingIfNotSet() {
        return !txPending_.exchange(true, std::memory_order_relaxed);
    }
    bool ConsumeTxPending() {
        return txPending_.exchange(false, std::memory_order_relaxed);
    }
    bool HasTxPending() const { return txPending_.load(std::memory_order_relaxed); }

private:
    Ngtcp2Connection() = default;

    bool InitClient(const ClientParams& params);
    bool InitTls();
    bool InitServer(const ServerInitParams& p);
    bool InitCommonCallbacks();

    // Processes one datagram; caller must hold opMu_ (BeginOpBlocking()).
    // Returns false once the connection reached a terminal state.
    bool ReadPacketLocked(const uint8_t* data, size_t len);

    // Wake readers of every stream that received data during the last read
    // batch. Must run on the IO thread right after draining the socket and
    // before Drive() (which may destroy closed streams).
    void FlushReadNotifyBatch();

    // Marks every stream this connection created as closed (EOF + write side
    // closed) and wakes its blocked readers/writers. An application can hold a
    // stream past the connection's lifetime (the pool drops its Client on a
    // node switch while the session keeps using the flow), so the close and the
    // destructor must release those waiters explicitly - otherwise they either
    // park forever or, in the old raw-pointer design, touched freed memory.
    void NotifyStreamsClosed();
    std::vector<Ngtcp2Stream*> readDirtyStreams_;

    // Release everything parked on this connection: the IO loop, the datagram
    // consumer, the accept waiters and the streams. Idempotent and safe to call
    // from any thread and any number of times, so every path that can end the
    // connection's life calls it - including the ones where the connection
    // closes itself and no owner asked for it.
    void WakeAllWaiters();

    // ngtcp2 callbacks (static trampolines to instance methods)
    static int SendPktCb(ngtcp2_conn* conn, const uint8_t* dgram, size_t dgramlen,
                         const ngtcp2_path* path, uint32_t flags, void* user_data);
    // Send one datagram through the right socket (client: connected socket;
    // server: listener's socket via sendto).
    //
    // This is the buffering entry point: when the target socket supports TX
    // segmentation and the packet matches the batch's segment size, the packet
    // is appended to txBatch_ instead of being sent, and the whole batch goes
    // out as one segmented syscall. Otherwise any pending batch is flushed
    // first (packet order must not change) and the packet is sent on its own.
    // Returns false only when a send actually failed.
    bool SendPacket(const uint8_t* data, size_t len);

    // The immediate, unbatched send: one syscall per packet. Kept separate so
    // the batching layer can fall back to it - both when a packet does not fit
    // the batch and when a segmented send is rejected or short.
    bool SendPacketNow(const uint8_t* data, size_t len);

    // Emit any buffered packets. No-op when the batch is empty. Returns false
    // if the segmented send failed and the per-packet fallback also failed.
    bool FlushTxBatch();

    void BuildPath(ngtcp2_path_storage* ps);
    void InternalLoop();
    // Write the wake byte to whichever pipe is valid (client pipe first,
    // then the listener's shared pipe for server connections).
    void WakePipeWrite();
    static int StreamOpenCb(ngtcp2_conn* conn, int64_t stream_id,
                            void* user_data);
    static int StreamCloseCb(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
                             uint64_t app_error_code, void* user_data,
                             void* stream_user_data);
    static int StreamResetCb(ngtcp2_conn* conn, int64_t stream_id, uint64_t final_size,
                             uint64_t app_error_code, void* user_data, void* stream_user_data);
    static int AckedStreamDataCb(ngtcp2_conn* conn, int64_t stream_id, uint64_t offset,
                                 uint64_t datalen, void* user_data, void* stream_user_data);
    static int DatagramRecvCb(ngtcp2_conn* conn, uint32_t flags, const uint8_t* data,
                              size_t datalen, void* user_data);
    static int DatagramSendCb(ngtcp2_conn* conn, uint64_t dgram_id, void* user_data);
    static int RecvStreamDataCb(ngtcp2_conn* conn, uint32_t flags, int64_t stream_id,
                                uint64_t offset, const uint8_t* data, size_t datalen,
                                void* user_data, void* stream_user_data);
    static void RandCb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx* rand_ctx);
    static int GetNewConnectionIdCb(ngtcp2_conn* conn, ngtcp2_cid* cid,
                                    ngtcp2_stateless_reset_token* token,
                                    size_t cidlen, void* user_data);

    // Pick a stream with pending (unsubmitted) write data. Caller must hold mu_.
    Ngtcp2Stream* PickWritableStreamLocked();
    // Round-robin cursor for PickWritableStreamLocked (protected by mu_).
    int64_t lastPickedStream_ = -1;
    // Cumulative ngtcp2_conn_read_pkt duration (HY2_BW_DIAG instrumentation).
    long long readPktNsAcc_ = 0;
    // Cumulative SendPacket duration (HY2_BW_DIAG instrumentation).
    long long sendNsAcc_ = 0;
    // Same, reported by the once-per-second DRIVE-BREAKDOWN line (kept apart
    // from sendNsAcc_ so the per-second [tx] report cannot zero it first).
    long long sendNsBreakdown_ = 0;
    // Socket send/drop counters snapshot (HY2_BW_DIAG instrumentation).
    UdpSocket::Stats sockStats_{};

    // Forward acked/lost packets to the congestion controller.
    void ReportAckedPackets(const ngtcp2_conn_info* cinfo);
    void ReportLostPackets();

    std::unique_ptr<UdpSocket> socket_;
    ngtcp2_conn* conn_ = nullptr;
    SSL* ssl_ = nullptr;
    SSL_CTX* sslCtx_ = nullptr;
    bool ownsSslCtx_ = false;
    ngtcp2_crypto_ossl_ctx* osslCtx_ = nullptr;
    ngtcp2_crypto_conn_ref connRef_{};

    ngtcp2_settings settings_{};
    ngtcp2_transport_params transportParams_{};
    ngtcp2_callbacks callbacks_{};

    mutable std::mutex mu_;
    // Streams owned by this connection
    std::unordered_map<int64_t, std::shared_ptr<Ngtcp2Stream>> streams_;
    // Streams removed from the map inside ngtcp2 callbacks; destroyed later
    // outside callback context (their destructors must not re-enter ngtcp2).
    std::vector<std::shared_ptr<Ngtcp2Stream>> zombieStreams_;

    // Pending incoming streams (server-side accepted via callback).
    // Protected by acceptMu_ (not mu_) so AcceptStream() can wait without
    // blocking the event loop's StreamOpenCb / RecvStreamDataCb.
    std::mutex acceptMu_;
    std::condition_variable acceptCv_;
    std::vector<std::shared_ptr<IQuicStream>> pendingAccepts_;

    std::mutex uniAcceptMu_;
    std::condition_variable uniAcceptCv_;
    std::vector<std::shared_ptr<IQuicStream>> pendingUniAccepts_;

    std::function<void(std::shared_ptr<IQuicStream>)> streamAcceptCb_;

    // Datagram receive queue. Guarded by datagramMu_ (NOT mu_): enqueueing a
    // datagram must not contend with stream callbacks / Drive's stream
    // picking. Deque so the consumer pops in O(1) (vector::erase(begin) was
    // O(N) per datagram and shifted the whole backlog).
    std::deque<std::vector<uint8_t>> recvDatagrams_;
    std::mutex datagramMu_;
    std::condition_variable datagramCv_;

    // Peer address (for SendPktCb)
    struct sockaddr_storage remoteAddr_{};
    socklen_t remoteAddrLen_ = 0;
    std::string remoteAddrStr_;
    struct sockaddr_storage localAddr_{};
    socklen_t localAddrLen_ = 0;

    // Non-owning: listener's socket used for server-side sends.
    UdpSocket* sendSocket_ = nullptr;

    // ---- TX segmentation batch -------------------------------------------
    // Windows can split one WSASendMsg into N datagrams of a fixed size
    // (UDP_SEND_MSG_SIZE). A bulk transfer emits packets of one identical
    // length (measured: 99.8% of them are exactly 1444 B), so batching those
    // into one syscall cuts the dominant per-packet cost - the send syscall is
    // 72-80% of this stack's per-packet CPU, and measured 2.3x lower per
    // datagram at 16 per call.
    //
    // All of this is guarded by opMu_: every caller of SendPacket (Drive,
    // SendDatagram, CloseWithError) holds it, so no lock is needed here.
    //
    // The segment size is LEARNED from the first full-size packet rather than
    // hard-coded, because it depends on the negotiated max_udp_payload_size and
    // the frame layout - a fixed constant would silently stop matching after
    // either changed.
    static constexpr size_t kTxBatchMax = 16;
    // Smallest packet treated as a bulk packet worth locking a segment size to;
    // below QUIC's 1200-byte floor a "full-size" guess would be wrong.
    static constexpr size_t kTxBatchMinSeg = 1200;
    bool txSegTried_ = false;   // EnableTxSegmentation attempted on this socket
    size_t txSegLen_ = 0;       // 0 = batching disabled (unsupported or not yet seen)
    std::vector<uint8_t> txBatch_;
    size_t txBatchCount_ = 0;

    // Non-owning: listener's wake pipe write-end for waking the event loop.
    // Set by Ngtcp2Listener when the connection is registered.
#ifdef _WIN32
    SOCKET* wakeWrite_ = nullptr;
    SOCKET clientWakeRead_ = INVALID_SOCKET;
    SOCKET clientWakeWrite_ = INVALID_SOCKET;
#else
    int* wakeWrite_ = nullptr;
    int clientWakeRead_ = -1;
    int clientWakeWrite_ = -1;
#endif

    // Client-owned wake pipe (mirrors Ngtcp2Listener's): lets Stream::Write
    // wake the InternalLoop immediately instead of waiting for the 10ms poll.
    // On Windows, select() on the UDP data socket ignores its timeout after
    // the handshake, so the loop waits on THIS pipe only (same as RecvLoop).
    void InitClientWakePipe();
    void CloseClientWakePipe();

    // Internal client loop
    std::thread loopThread_;
    std::atomic<bool> stopLoop_{false};
    std::atomic<bool> loopRunning_{false};

    // Server-side worker loop state
    void ServerLoop();
    std::deque<std::vector<uint8_t>> rxQueue_;
    // Recycled datagram buffers for the listener -> worker handoff: avoids
    // one malloc/free per received packet.
    std::vector<std::vector<uint8_t>> rxPool_;
    // Edge trigger for rxCv_: the listener only wakes the worker on the first
    // enqueue after the worker drained the queue (guarded by rxMu_).
    bool rxNotifyArmed_ = false;
    std::mutex rxMu_;
    std::condition_variable rxCv_;
    std::thread serverLoopThread_;
    std::atomic<bool> serverLoopStop_{false};
    std::atomic<bool> serverLoopRunning_{false};
    static constexpr size_t kMaxRxQueue = 8192;
    static constexpr size_t kMaxRxPool = 8192;

    // Cached ngtcp2 path (local/remote addresses never change after init).
    ngtcp2_path_storage cachedPath_{};
    bool cachedPathReady_ = false;
    ngtcp2_path* GetPath();

    std::atomic<bool> handshakeComplete_{false};
    std::condition_variable handshakeCv_;
    // Bound for waiting on the handshake (QuicConfig::HandshakeTimeout, 10s
    // default). Node probing uses a short one so unreachable nodes fail fast.
    std::chrono::milliseconds handshakeTimeout_{10000};
    std::atomic<bool> closed_{false};
    std::atomic<bool> datagramTxEnabled_{false};
    std::atomic<bool> txPending_{false};
    std::mutex opMu_;

    // ngtcp2 connection IDs (must outlive conn_)
    ngtcp2_cid dcid_{};
    ngtcp2_cid scid_{};

    // Client params (must outlive conn_)
    ClientParams params_{};

    // RTT stats bridged to congestion controller
    RttStats rttStats_;

    // Previous conn_stat for delta computation
    ngtcp2_conn_info prevStat_{};
    ngtcp2_conn_info cinfo2_{};

    std::string localAddrStr_;

    Ngtcp2Listener* listener_ = nullptr;

    // ---- Runtime diagnostics (enabled by HY2_BW_DIAG=1) ----
    struct Diag {
        // SendDatagram stats
        std::atomic<uint64_t> dgramTxCalls{0};
        std::atomic<uint64_t> dgramTxSuccess{0};
        std::atomic<uint64_t> dgramTxAccepted0{0};
        std::atomic<uint64_t> dgramTxRv0{0};
        std::atomic<uint64_t> dgramTxRvNeg{0};
        std::atomic<uint64_t> dgramTxLockWaitNs{0};
        std::atomic<uint64_t> dgramTxLockHoldNs{0};

        // InternalLoop stats
        std::atomic<uint64_t> loopCount{0};
        std::atomic<uint64_t> recvPackets{0};
        std::atomic<uint64_t> ackPackets{0};
        std::atomic<uint64_t> driveCalls{0};
        std::atomic<uint64_t> driveNs{0};

        // OnUdpRecv / ACK stats
        std::atomic<uint64_t> readPktCalls{0};
        std::atomic<uint64_t> ackProcessed{0};

        // Actual UDP send tracking (SendPacket level)
        std::atomic<uint64_t> sendPacketSuccess{0};
        std::atomic<uint64_t> sendPacketFail{0};

        // Lock contention
        std::atomic<uint64_t> drivingLockAcquires{0};
        std::atomic<uint64_t> drivingLockContentions{0};
        std::atomic<uint64_t> drivingLockWaitNs{0};
        std::atomic<uint64_t> drivingLockHoldNs{0};

        // Congestion snapshot (updated each Drive)
        std::atomic<uint64_t> lastCwnd{0};
        std::atomic<uint64_t> lastInflight{0};
        std::atomic<uint64_t> lastBytesSent{0};
        std::atomic<int64_t>  lastSmoothedRttNs{0};

        void Print(const char* tag) const;
        void Reset();
    };
    Diag diag_;

public:
    // Runtime diagnostic counters. Exposed so tests can assert that the
    // default path (HY2_BW_DIAG unset) never touches them: they must stay
    // zero unless diagnostics are explicitly enabled.
    const Diag& DiagCounters() const { return diag_; }
};

} // namespace hy2::quic_backend


