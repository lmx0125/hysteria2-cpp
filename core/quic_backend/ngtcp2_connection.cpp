#include "hy2/quic_backend/ngtcp2_connection.hpp"
#include "hy2/diag/lock_diag.hpp"

#ifdef _WIN32
#pragma comment(lib, "winmm.lib")
#endif

#include <cstring>
#include "hy2/diag/lock_diag.hpp"
#include <cstdio>
#include "hy2/diag/lock_diag.hpp"
#include <cstdlib>
#include "hy2/diag/lock_diag.hpp"
#include <cstdarg>
#include "hy2/diag/lock_diag.hpp"
#include <algorithm>
#include "hy2/diag/lock_diag.hpp"
#include <chrono>
#include "hy2/diag/lock_diag.hpp"
#include <iostream>
#include "hy2/diag/lock_diag.hpp"
#include <limits>
#include "hy2/diag/lock_diag.hpp"

#ifdef _WIN32
  #include <winsock2.h>
  #include <mmsystem.h>
  #pragma comment(lib, "winmm.lib")
#else
  #include <unistd.h>
  #include <fcntl.h>
  #include <arpa/inet.h>
#endif

#include <ngtcp2/ngtcp2.h>
#include "hy2/diag/lock_diag.hpp"
#include <ngtcp2/ngtcp2_crypto.h>
#include "hy2/diag/lock_diag.hpp"
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include "hy2/diag/lock_diag.hpp"
#include <openssl/err.h>
#include "hy2/diag/lock_diag.hpp"
#include <openssl/ssl.h>
#include "hy2/diag/lock_diag.hpp"
#include <openssl/rand.h>
#include "hy2/diag/lock_diag.hpp"

#include "hy2/quic_backend/udp_socket.hpp"
#include "hy2/diag/lock_diag.hpp"
#include "hy2/quic_backend/io_poll.hpp"
#include "hy2/diag/lock_diag.hpp"
#include "hy2/quic_backend/ngtcp2_stream.hpp"
#include "hy2/diag/lock_diag.hpp"
#include "hy2/quic_backend/ngtcp2_listener.hpp"
#include "hy2/diag/lock_diag.hpp"
#include "hy2/protocol.hpp"
#include "hy2/diag/lock_diag.hpp"

void (*g_hy2TraceSink)(uint32_t tag, int64_t rv) = nullptr;
#define TTRACE(tag, rv) do { if (g_hy2TraceSink) g_hy2TraceSink((tag), (int64_t)(rv)); } while (0)
#define DBG(msg) do { if (std::getenv("HY2_QUIC_DEBUG")) std::fprintf(stderr, "[dbg] %s\n", msg); } while(0)

// --- Diagnostic: handshake timeline ---
static std::chrono::steady_clock::time_point g_connStartTime;
static std::atomic<int> g_txPackets{0};
static std::atomic<int> g_txBytes{0};
static std::atomic<int> g_rxPackets{0};
static std::atomic<int> g_rxBytes{0};
static std::atomic<bool> g_initialSent{false};
static std::atomic<bool> g_handshakeCompleted{false};
static std::once_flag g_cryptoInitFlag;
// Cached once: keeps the per-packet hot path free of getenv()/diag work when
// diagnostics are disabled (the default).
// Lazy: a file-scope static initialises before main(), so a flag set
// from the app (--debug) could never turn the diagnostics on.
static bool Hy2DiagEnabled() {
    static const bool v = std::getenv("HY2_BW_DIAG") != nullptr ||
                          std::getenv("HY2_DIAG") != nullptr;
    return v;
}

static const char* QuicPacketTypeName(uint8_t firstByte) {
    uint8_t form = (firstByte >> 7) & 1;
    uint8_t typeBits = (firstByte >> 4) & 0x03;
    if (form == 0) return "Long";
    // Short header: form=1, fixed=1, spin=0-1
    return "Short";
}

static const char* QuicLongPacketTypeName(uint8_t firstByte) {
    uint8_t typeBits = (firstByte >> 4) & 0x03;
    switch (typeBits) {
        case 0x00: return "Initial";
        case 0x01: return "0-RTT";
        case 0x02: return "Handshake";
        case 0x03: return "Retry";
        default:   return "Unknown";
    }
}

static double ElapsedMs() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - g_connStartTime).count();
}

namespace hy2::quic_backend {

// HY2_DIAG: count of Drive() calls that ended with ngtcp2 reporting "nothing
// writable" (congestion/flow-control blocked). Printed by ConnHeartbeat().
static std::atomic<uint64_t> g_driveRv0{0};

static bool QuicDebugEnabled() {
    static bool v = std::getenv("HY2_QUIC_DEBUG") != nullptr;
    return v;
}

static ngtcp2_tstamp NowTimestamp() {
    return static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// ---------------------------------------------------------------------------
// RttStats
// ---------------------------------------------------------------------------
Duration RttStats::MinRTT() const { return minRTT_; }
Duration RttStats::LatestRTT() const { return latestRTT_; }
Duration RttStats::SmoothedRTT() const { return smoothedRTT_; }
Duration RttStats::MeanDeviation() const { return meanDeviation_; }

void RttStats::Update(Duration latestRTT) {
    latestRTT_ = latestRTT;
    if (!hasSample_) {
        minRTT_ = latestRTT;
        smoothedRTT_ = latestRTT;
        meanDeviation_ = Duration::FromNanos(0);
        hasSample_ = true;
        return;
    }
    if (latestRTT < minRTT_) minRTT_ = latestRTT;
    // RFC 6298
    int64_t absDiff = latestRTT.ns - smoothedRTT_.ns;
    if (absDiff < 0) absDiff = -absDiff;
    meanDeviation_ = Duration::FromNanos(
        (3 * meanDeviation_.ns + absDiff) / 4);
    smoothedRTT_ = Duration::FromNanos(
        (7 * smoothedRTT_.ns + latestRTT.ns) / 8);
}

// ---------------------------------------------------------------------------
// ngtcp2 callback trampolines
// ---------------------------------------------------------------------------

int Ngtcp2Connection::SendPktCb(ngtcp2_conn* /*conn*/,
                                 const uint8_t* dgram, size_t dgramlen,
                                 const ngtcp2_path* /*path*/,
                                 uint32_t /*flags*/, void* user_data) {
    auto* self = static_cast<Ngtcp2Connection*>(user_data);
    if (!self) return NGTCP2_ERR_CALLBACK_FAILURE;
    if (!self->SendPacket(dgram, dgramlen)) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

bool Ngtcp2Connection::SendPacket(const uint8_t* data, size_t len) {
    // All counters/timers below are diagnostics: gated on the cached flag so
    // the default path has no atomic RMWs and no clock reads per packet.
    std::chrono::steady_clock::time_point spStart;
    if (Hy2DiagEnabled()) {
        if (len > 0) {
            g_txPackets.fetch_add(1, std::memory_order_relaxed);
            g_txBytes.fetch_add(static_cast<int>(len), std::memory_order_relaxed);
        }
        spStart = std::chrono::steady_clock::now();
    }
    bool result = false;
    if (socket_) {
        result = socket_->Send(data, len) >= 0;
    } else if (sendSocket_ && remoteAddrLen_ > 0) {
        result = sendSocket_->SendTo(data, len,
                                   reinterpret_cast<const struct sockaddr*>(&remoteAddr_),
                                   remoteAddrLen_) >= 0;
    }
    if (Hy2DiagEnabled()) {
        const auto dt = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - spStart).count();
        sendNsAcc_ += dt;
        sendNsBreakdown_ += dt;
        // Per-second TX report: the decisive split between "we cannot send"
        // (cwnd / peer) and "the local socket is the bottleneck". sendto_ms
        // close to 1000 means the kernel/UDP path is saturated; near 0 with a
        // low rate means the data is not being handed to us fast enough.
        {
            static std::mutex repMu;
            static int64_t nextMs = 0;
            const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            if (nowMs >= nextMs) {
                std::lock_guard<std::mutex> rl(repMu);
                if (nowMs >= nextMs) {
                    const long long sentNs = static_cast<long long>(sendNsAcc_);
                    sendNsAcc_ = 0;
                    std::fprintf(stderr, "[tx] 1s pkts=%llu bytes=%lluKB sendto_ms=%lld\n",
                                 (unsigned long long)g_txPackets.exchange(0),
                                 (unsigned long long)(g_txBytes.exchange(0) / 1024),
                                 (long long)(sentNs / 1000000));
                    std::fflush(stderr);
                    nextMs = nowMs + 1000;
                }
            }
        }
        if (result) {
            diag_.sendPacketSuccess.fetch_add(1, std::memory_order_relaxed);
        } else {
            diag_.sendPacketFail.fetch_add(1, std::memory_order_relaxed);
            std::fprintf(stderr, "[SENDPKT-FAIL] len=%zu\n", len);
        }
    }
    return result;
}

void Ngtcp2Connection::BuildPath(ngtcp2_path_storage* ps) {
    ngtcp2_path_storage_zero(ps);
    if (localAddrLen_ > 0) {
        ps->path.local.addr = reinterpret_cast<struct sockaddr*>(&localAddr_);
        ps->path.local.addrlen = localAddrLen_;
    }
    if (remoteAddrLen_ > 0) {
        ps->path.remote.addr = reinterpret_cast<struct sockaddr*>(&remoteAddr_);
        ps->path.remote.addrlen = remoteAddrLen_;
    }
}

// The path (local/remote addresses) never changes after the connection is
// initialised, so build it once and reuse it in the per-packet hot paths.
ngtcp2_path* Ngtcp2Connection::GetPath() {
    if (!cachedPathReady_) {
        BuildPath(&cachedPath_);
        cachedPathReady_ = true;
    }
    return &cachedPath_.path;
}

int Ngtcp2Connection::StreamOpenCb(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                    void* user_data) {
    auto* self = static_cast<Ngtcp2Connection*>(user_data);
    if (!self) return NGTCP2_ERR_CALLBACK_FAILURE;

    bool bidi = (stream_id & 0x2) == 0;
    DBG_LOG("[StreamOpenCb] stream_id", stream_id, "bidi", bidi);

    // weak_from_this() (not shared_from_this()) so a throw can never escape
    // into ngtcp2's C callback: a callback only runs while Connect()/
    // CreateServer() already own the connection, so the lock is non-empty.
    auto stream = std::shared_ptr<Ngtcp2Stream>(
        new Ngtcp2Stream(self->weak_from_this().lock(), stream_id));
    {
        std::lock_guard<std::mutex> lk(self->mu_);
        auto it = self->streams_.find(stream_id);
        if (it != self->streams_.end()) {
            return 0;
        }
        self->streams_[stream_id] = stream;
    }
    // Add to pending queue under acceptMu_ (NOT mu_) so AcceptStream() can
    // wait without blocking the event loop.
    if (bidi) {
        {
            std::lock_guard<std::mutex> lk(self->acceptMu_);
            self->pendingAccepts_.push_back(stream);
        }
        self->acceptCv_.notify_one();
    } else {
        {
            std::lock_guard<std::mutex> lk(self->uniAcceptMu_);
            self->pendingUniAccepts_.push_back(stream);
        }
        self->uniAcceptCv_.notify_one();
    }
    return 0;
}

int Ngtcp2Connection::StreamCloseCb(ngtcp2_conn* /*conn*/, uint32_t /*flags*/,
                                     int64_t stream_id,
                                     uint64_t app_error_code, void* user_data,
                                     void* /*stream_user_data*/) {
    auto* self = static_cast<Ngtcp2Connection*>(user_data);
    if (!self) return 0;
    std::lock_guard<std::mutex> lk(self->mu_);
    auto it = self->streams_.find(stream_id);
    if (it != self->streams_.end()) {
        it->second->OnStreamClose(app_error_code);
        // Defer destruction: a shared_ptr release inside this callback
        // could run ~Ngtcp2Stream while ngtcp2 is mid-callback.
        self->zombieStreams_.push_back(std::move(it->second));
        self->streams_.erase(it);
    }
    return 0;
}

int Ngtcp2Connection::StreamResetCb(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                     uint64_t final_size, uint64_t app_error_code,
                                     void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<Ngtcp2Connection*>(user_data);
    if (!self) return 0;
    std::lock_guard<std::mutex> lk(self->mu_);
    auto it = self->streams_.find(stream_id);
    if (it != self->streams_.end()) {
        it->second->OnStreamReset(final_size, app_error_code);
    }
    return 0;
}

int Ngtcp2Connection::AckedStreamDataCb(ngtcp2_conn* /*conn*/, int64_t stream_id,
                                          uint64_t offset, uint64_t datalen,
                                          void* user_data,
                                          void* /*stream_user_data*/) {
    auto* self = static_cast<Ngtcp2Connection*>(user_data);
    if (!self) return 0;
    std::lock_guard<std::mutex> lk(self->mu_);
    auto it = self->streams_.find(stream_id);
    if (it != self->streams_.end()) {
        it->second->OnAckedStreamData(offset, datalen);
    }
    return 0;
}

int Ngtcp2Connection::DatagramRecvCb(ngtcp2_conn* /*conn*/, uint32_t /*flags*/,
                                      const uint8_t* data,
                                      size_t datalen, void* user_data) {
    auto* self = static_cast<Ngtcp2Connection*>(user_data);
    if (!self) return 0;
    {
        // Dedicated mutex (not mu_): datagram enqueue must not contend with
        // stream callbacks / Drive's stream picking on mu_.
        std::lock_guard<std::mutex> lk(self->datagramMu_);
        // Edge-triggered wake: only the empty->non-empty transition needs to
        // notify. When the queue was already non-empty (a burst), the
        // consumer is either running (it re-checks the predicate under the
        // mutex before parking) or about to check - no wake needed.
        const bool wasEmpty = self->recvDatagrams_.empty();
        self->recvDatagrams_.emplace_back(data, data + datalen);
        if (wasEmpty) self->datagramCv_.notify_one();
    }
    return 0;
}

int Ngtcp2Connection::DatagramSendCb(ngtcp2_conn* /*conn*/,
                                      uint64_t /*dgram_id*/, void* /*user_data*/) {
    return 0;
}

int Ngtcp2Connection::RecvStreamDataCb(ngtcp2_conn* conn, uint32_t flags,
                                        int64_t stream_id, uint64_t offset,
                                        const uint8_t* data, size_t datalen,
                                        void* user_data, void* /*stream_user_data*/) {
    auto* self = static_cast<Ngtcp2Connection*>(user_data);
    if (!self) return NGTCP2_ERR_CALLBACK_FAILURE;

    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[dbg] RecvStreamData: sid=%llu len=%zu fin=%d offset=%llu\n",
                     (unsigned long long)stream_id, datalen,
                     (int)((flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0),
                     (unsigned long long)offset);
    }

    std::shared_ptr<Ngtcp2Stream> stream;
    bool streamIsNew = false;
    bool bidi = false;
    {
        std::lock_guard<std::mutex> lk(self->mu_);
        auto it = self->streams_.find(stream_id);
        if (it != self->streams_.end()) {
            stream = it->second;
        } else {
            // Stream not found in our map �� create it on first data receipt.
            // This handles the case where ngtcp2 1.25.0 delivers data before
            // (or instead of) invoking the stream_open callback.
            bidi = (stream_id & 0x2) == 0;
            stream = std::shared_ptr<Ngtcp2Stream>(
                new Ngtcp2Stream(self->weak_from_this().lock(), stream_id));
            self->streams_[stream_id] = stream;
            streamIsNew = true;
            if (std::getenv("HY2_QUIC_DEBUG")) {
                std::fprintf(stderr, "[dbg] RecvStreamData: CREATED stream sid=%llu bidi=%d (stream_open was not called)\n",
                             (unsigned long long)stream_id, (int)bidi);
            }
        }
    }
    // Add to pending queue under acceptMu_ (NOT mu_) so AcceptStream() can
    // wait without blocking the event loop.
    if (streamIsNew) {
        if (bidi) {
            {
                std::lock_guard<std::mutex> lk(self->acceptMu_);
                self->pendingAccepts_.push_back(stream);
            }
            self->acceptCv_.notify_one();
        } else {
            {
                std::lock_guard<std::mutex> lk(self->uniAcceptMu_);
                self->pendingUniAccepts_.push_back(stream);
            }
            self->uniAcceptCv_.notify_one();
        }
    }

    if (datalen > 0) {
        DBG_LOG("[RecvStreamDataCb] stream_id", stream_id, "datalen", datalen, "new", streamIsNew);
        stream->OnStreamData(data, datalen, false);
    }
    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        stream->OnStreamData(nullptr, 0, true); // signal EOF
    }
    // Defer the reader wakeup to FlushReadNotifyBatch() (one notify per
    // received batch instead of one per packet). Bounded to avoid unbounded
    // growth if a flush is skipped while the connection is closing.
    if ((datalen > 0 || (flags & NGTCP2_STREAM_DATA_FLAG_FIN)) &&
        self->readDirtyStreams_.size() < 4096) {
        self->readDirtyStreams_.push_back(stream.get());
    }

    // NOTE: the receive window is NOT extended here. Credit is returned by
    // Ngtcp2Stream::Read() -> ExtendReadCredit() for the bytes the application
    // actually consumed. Extending on arrival (the previous >=1 MB per chunk
    // behavior) let a slow reader's peer send without bound and made
    // Ngtcp2Stream::readBuf_ grow at line rate.

    (void)offset;
    return 0;
}

void Ngtcp2Connection::RandCb(uint8_t* dest, size_t destlen,
                               const ngtcp2_rand_ctx* /*rand_ctx*/) {
    if (RAND_bytes(dest, static_cast<int>(destlen)) != 1) {
        // Fall back to a weak source rather than failing hard.
        for (size_t i = 0; i < destlen; ++i) {
            dest[i] = static_cast<uint8_t>(std::rand() & 0xFF);
        }
    }
}

int Ngtcp2Connection::GetNewConnectionIdCb(ngtcp2_conn* /*conn*/, ngtcp2_cid* cid,
                                            ngtcp2_stateless_reset_token* token,
                                            size_t cidlen, void* /*user_data*/) {
    if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    if (RAND_bytes(token->data, static_cast<int>(sizeof(token->data))) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

Ngtcp2Stream* Ngtcp2Connection::PickWritableStreamLocked() {
    // Round-robin: resume from the stream after the last one picked so a
    // hot stream cannot starve its siblings (Drive re-picks per packet
    // and an unordered_map always yields the same first entry).
    auto it = streams_.find(lastPickedStream_);
    if (it != streams_.end()) ++it;
    for (size_t i = 0; i < streams_.size(); ++i) {
        if (it == streams_.end()) it = streams_.begin();
        // Closed streams still need to flush queued data + FIN.
        if (it->second && it->second->HasPendingWrite()) {
            lastPickedStream_ = it->first;
            return it->second.get();
        }
        ++it;
    }
    return nullptr;
}

bool Ngtcp2Connection::InitCommonCallbacks() {
    // TLS glue callbacks (shared crypto lib - works with ossl backend).
    memset(&callbacks_, 0, sizeof(callbacks_));
    callbacks_.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks_.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks_.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks_.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks_.rand = RandCb;
    callbacks_.update_key = ngtcp2_crypto_update_key_cb;
    callbacks_.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks_.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks_.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks_.get_new_connection_id2 = GetNewConnectionIdCb;
    callbacks_.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;

    // Application-level callbacks
    callbacks_.stream_open = StreamOpenCb;
    callbacks_.stream_close = StreamCloseCb;
    callbacks_.stream_reset = StreamResetCb;
    callbacks_.recv_stream_data = RecvStreamDataCb;
    callbacks_.acked_stream_data_offset = AckedStreamDataCb;
    callbacks_.ack_datagram = DatagramSendCb;
    callbacks_.recv_datagram = DatagramRecvCb;
    return true;
}

static ngtcp2_cc_algo SelectCcAlgo(const std::string& type,
                                   ngtcp2_cc_algo fallback) {
    // HY2_CC_ALGO=brr|bbr|cubic|reno|brutal overrides the congestion control
    // (diagnostics / A/B testing). "brutal" needs a declared send rate
    // (QuicConfig::BrutalRate) to be armed; without one it only does
    // ACK-clocked growth with a simple loss response.
    const char* v = std::getenv("HY2_CC_ALGO");
    if (v) {
        if (std::strcmp(v, "brr") == 0 || std::strcmp(v, "bbr") == 0) return NGTCP2_CC_ALGO_BBR;
        if (std::strcmp(v, "cubic") == 0) return NGTCP2_CC_ALGO_CUBIC;
        if (std::strcmp(v, "reno") == 0) return NGTCP2_CC_ALGO_RENO;
        if (std::strcmp(v, "brutal") == 0) return NGTCP2_CC_ALGO_BRUTAL;
    }
    // Config-driven selection. "brutal" is the fixed-rate, loss-insensitive
    // controller (Hysteria's sender); it is selected automatically when a
    // send bandwidth is declared (see client.cpp/server.cpp).
    if (type == "brutal") return NGTCP2_CC_ALGO_BRUTAL;
    if (type == "bbr") return NGTCP2_CC_ALGO_BBR;
    if (type == "cubic") return NGTCP2_CC_ALGO_CUBIC;
    if (type == "reno") return NGTCP2_CC_ALGO_RENO;
    return fallback;
}

static void FillTransportParams(ngtcp2_transport_params* tp, const QuicConfig& cfg,
                                bool datagramEnabled,
                                bool disableChromeParrot = true) {
    ngtcp2_transport_params_default(tp);
    // Map QuicConfig to ngtcp2 transport parameters, matching quic-go's mapping.
    //
    // ngtcp2                                quic-go Config
    // �������������������������������������������������������������������������� ������������������������������������������������������������������������
    // initial_max_streams_bidi              MaxIncomingStreams (server only)
    // initial_max_data                      InitialConnectionReceiveWindow
    // initial_max_stream_data_bidi_local    InitialStreamReceiveWindow
    // initial_max_stream_data_bidi_remote   InitialStreamReceiveWindow
    // initial_max_stream_data_uni           (not in Hy2 config, use reasonable default)
    // initial_max_streams_uni               (not in Hy2 config, use reasonable default)
    // max_datagram_frame_size               MaxDatagramFrameSize (protocol constant)
    // max_idle_timeout                      MaxIdleTimeout

    tp->initial_max_streams_bidi =
        cfg.MaxIncomingStreams > 0
            ? static_cast<uint64_t>(cfg.MaxIncomingStreams)
            : 128;  // reasonable default when not configured
    tp->initial_max_streams_uni = 8;
    tp->initial_max_data =
        cfg.InitialConnectionReceiveWindow > 0
            ? cfg.InitialConnectionReceiveWindow
            : 16 * 1048576;  // 16MB default
    tp->initial_max_stream_data_bidi_local =
        cfg.InitialStreamReceiveWindow > 0
            ? cfg.InitialStreamReceiveWindow
            : 8 * 1048576;   // 8MB default
    tp->initial_max_stream_data_bidi_remote =
        cfg.InitialStreamReceiveWindow > 0
            ? cfg.InitialStreamReceiveWindow
            : 8 * 1048576;   // 8MB default
    tp->initial_max_stream_data_uni = 8 * 1048576;  // 8MB per uni stream (not configurable)
    // ACK quickly: ngtcp2's default 25ms max_ack_delay serializes ACKs,
    // which caps the sender's slow-start ramp (each ACK releases only the
    // few acked packets). 1ms keeps the receiver responsive on loopback.
    tp->max_ack_delay = NGTCP2_MILLISECONDS;
    if (datagramEnabled) {
        // Advertise the protocol max DATAGRAM payload (1200) plus the
        // frame type + length overhead (3): both ngtcp2 and quic-go cap
        // the payload they SEND at the peer's advertised value minus the
        // frame header (quic-go: DatagramFrame.MaxDataLen). Advertising
        // exactly 1200 would silently shrink the usable payload to 1197.
        tp->max_datagram_frame_size = proto::kMaxDatagramFrameSize + 3;  // 1203
    }
    if (cfg.MaxIdleTimeout.ns > 0) {
        tp->max_idle_timeout =
            static_cast<uint64_t>(cfg.MaxIdleTimeout.Milliseconds()) *
            NGTCP2_MILLISECONDS;
    }

    // ChromeParrot overrides: when DisableChromeParrot=false, use Chrome's
    // transport parameter values to match the official hy2-go behavior.
    // These values come from quic-go chrome_parrot.go and config.go:109-125.
    // ChromeParrot unconditionally overrides user-configured values.
    if (!disableChromeParrot) {
        tp->initial_max_streams_bidi = 100;                     // chromeMaxIncomingStreams
        tp->initial_max_streams_uni = 103;                      // chromeMaxIncomingUniStreams
        tp->initial_max_data = 15728640;                        // chromeInitialMaxData
        tp->initial_max_stream_data_bidi_local = 6291456;       // chromeInitialMaxStreamData
        tp->initial_max_stream_data_bidi_remote = 6291456;      // chromeInitialMaxStreamData
        tp->max_udp_payload_size = 1472;                        // chromeMaxUDPPayloadSize
        if (datagramEnabled) {
            tp->max_datagram_frame_size = 65536;                // chromeMaxDatagramFrameSize
        }
    }
}

static void Ngtcp2LogPrintf(void* /*user_data*/, const char* format, ...) {
    va_list args;
    va_start(args, format);
    std::vfprintf(stderr, format, args);
    va_end(args);
    std::fprintf(stderr, "\n");
}

// ---------------------------------------------------------------------------
// Server-side connection creation
// ---------------------------------------------------------------------------

std::shared_ptr<Ngtcp2Connection> Ngtcp2Connection::CreateServer(
    const ServerInitParams& p) {

    auto self = std::shared_ptr<Ngtcp2Connection>(new Ngtcp2Connection());
    if (!self->InitServer(p)) return nullptr;
    return self;
}

bool Ngtcp2Connection::InitServer(const ServerInitParams& p) {
    bool initOk = true;
    std::call_once(g_cryptoInitFlag, [&]() {
        if (ngtcp2_crypto_ossl_init() != 0) initOk = false;
    });
    if (!initOk) return false;

    listener_ = p.listener;
    sslCtx_ = p.sslCtx;
    ownsSslCtx_ = false;
    if (p.listener) {
        sendSocket_ = p.listener->GetSocketRaw();
    }
    if (p.localAddr && p.localAddrLen > 0) {
        memcpy(&localAddr_, p.localAddr, p.localAddrLen);
        localAddrLen_ = p.localAddrLen;
    }

    if (!InitCommonCallbacks()) return false;
    // Server-side TLS callback
    callbacks_.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;

    const std::string ccCfg = p.quicCfg.CongestionControl;
    ngtcp2_settings_default(&settings_);
    settings_.cc_algo = SelectCcAlgo(ccCfg, NGTCP2_CC_ALGO_BBR);  // Config-selected CC; BBR by default (HY2_CC_ALGO overrides for A/B tests)
    settings_.initial_ts = NowTimestamp();
    settings_.max_tx_udp_payload_size = 1452;  // IPv4/UDP max without fragmentation on a 1500 MTU path
    // HY2: ACK every packet immediately (default batches every 2 packets or
    // max_ack_delay). On a poll-based loop, batching delays the sender's
    // cwnd feedback and stalls the slow-start ramp.
    settings_.ack_thresh = 1;
    if (std::getenv("HY2_QUIC_DEBUG")) {
        settings_.log_printf = Ngtcp2LogPrintf;
    }

    FillTransportParams(&transportParams_, p.quicCfg, p.datagramEnabled);

    // Server must report the DCID from the client's Initial packet.
    transportParams_.original_dcid_present = 1;
    transportParams_.original_dcid = p.hd->dcid;

    // dcid = client's SCID; scid = server-chosen random CID
    dcid_ = p.hd->scid;
    scid_.datalen = 8;
    RAND_bytes(scid_.data, static_cast<int>(scid_.datalen));

    ngtcp2_path path;
    path.local.addr = const_cast<struct sockaddr*>(p.localAddr);
    path.local.addrlen = p.localAddrLen;
    path.remote.addr = const_cast<struct sockaddr*>(p.remoteAddr);
    path.remote.addrlen = p.remoteAddrLen;

    DBG("server: calling conn_server_new");
    int rv = ngtcp2_conn_server_new(&conn_, &dcid_, &scid_, &path,
                                    p.hd->version,
                                    &callbacks_, &settings_,
                                    &transportParams_, nullptr, this);
    if (rv != 0) {
        return false;
    }

    if (p.quicCfg.HandshakeTimeout.ns > 0) {
        handshakeTimeout_ = std::chrono::milliseconds(p.quicCfg.HandshakeTimeout.ns / 1000000);
    }
    // Declared send rate -> in-stack Brutal controller (see QuicConfig).
    // The rate is refined after the handshake with min(client Rx, MaxTx).
    if (settings_.cc_algo == NGTCP2_CC_ALGO_BRUTAL && p.quicCfg.BrutalRate > 0) {
        ngtcp2_conn_set_brutal_rate(conn_, p.quicCfg.BrutalRate);
    }

    // Server SSL session
    DBG("server: new ssl");
    ssl_ = SSL_new(sslCtx_);
    if (!ssl_) return false;
    SSL_set_accept_state(ssl_);
    if (ngtcp2_crypto_ossl_configure_server_session(ssl_) != 0) {
        return false;
    }
    // ALPN is selected by the listener's SSL_CTX select callback
    // (servers must not use SSL_set_alpn_protos).

    if (ngtcp2_crypto_ossl_ctx_new(&osslCtx_, ssl_) != 0) {
        return false;
    }
    ngtcp2_conn_set_tls_native_handle(conn_, osslCtx_);

    DBG("server: ctx+native_handle");
    connRef_.get_conn = [](ngtcp2_crypto_conn_ref* ref) -> ngtcp2_conn* {
        auto* self = static_cast<Ngtcp2Connection*>(ref->user_data);
        return self ? self->conn_ : nullptr;
    };
    connRef_.user_data = this;
    SSL_set_app_data(ssl_, &connRef_);

    // Remote address bookkeeping
    DBG("server: addr bookkeeping");
    char host[INET6_ADDRSTRLEN] = {};
    uint16_t port = 0;
    if (p.remoteAddr->sa_family == AF_INET) {
        auto* sin = reinterpret_cast<const struct sockaddr_in*>(p.remoteAddr);
        inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
        port = ntohs(sin->sin_port);
        remoteAddrStr_ = std::string(host) + ":" + std::to_string(port);
    } else if (p.remoteAddr->sa_family == AF_INET6) {
        auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(p.remoteAddr);
        inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
        port = ntohs(sin6->sin6_port);
        remoteAddrStr_ = std::string(host) + ":" + std::to_string(port);
    }
    memcpy(&remoteAddr_, p.remoteAddr, p.remoteAddrLen);
    remoteAddrLen_ = p.remoteAddrLen;

    return true;
}

// ---------------------------------------------------------------------------
// Connection lifecycle
// ---------------------------------------------------------------------------

bool Ngtcp2Connection::InitTls() {
    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms InitTls: creating SSL\n", ElapsedMs());
    }
    ssl_ = SSL_new(sslCtx_);
    if (!ssl_) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms InitTls: SSL_new FAILED err=%lu\n",
                         ElapsedMs(), (unsigned long)ERR_get_error());
        }
        return false;
    }

    SSL_set_connect_state(ssl_); // client mode

    if (ngtcp2_crypto_ossl_configure_client_session(ssl_) != 0) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms InitTls: ossl_configure_client_session FAILED\n",
                         ElapsedMs());
        }
        SSL_free(ssl_);
        ssl_ = nullptr;
        return false;
    }

    // SNI
    std::string sni = params_.serverName.empty() ? params_.remoteAddr
                                                 : params_.serverName;
    if (!SSL_set_tlsext_host_name(ssl_, const_cast<char*>(sni.c_str()))) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms InitTls: SSL_set_tlsext_host_name FAILED\n",
                         ElapsedMs());
        }
        SSL_free(ssl_);
        ssl_ = nullptr;
        return false;
    }

    // ALPN: HTTP/3 (required by Hysteria2)
    static const unsigned char alpn[] = {2, 'h', '3'};
    if (SSL_set_alpn_protos(ssl_, alpn, sizeof(alpn)) != 0) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms InitTls: SSL_set_alpn_protos FAILED\n",
                         ElapsedMs());
        }
        SSL_free(ssl_);
        ssl_ = nullptr;
        return false;
    }

    // Certificate verification
    if (params_.insecureSkipVerify) {
        SSL_set_verify(ssl_, SSL_VERIFY_NONE, nullptr);
    }

    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms InitTls: OK sni=%s alpn=h3 insecure=%d\n",
                     ElapsedMs(), sni.c_str(), params_.insecureSkipVerify ? 1 : 0);
    }

    return true;
}

std::shared_ptr<Ngtcp2Connection> Ngtcp2Connection::Connect(
    const ClientParams& params, cc::CongestionControl* /*ccOverride*/) {

    auto self = std::shared_ptr<Ngtcp2Connection>(new Ngtcp2Connection());
    if (!self->InitClient(params)) return nullptr;
    self->StartInternalLoop();
    return self;
}

bool Ngtcp2Connection::InitClient(const ClientParams& params) {
#ifdef _WIN32
    // 1ms timer resolution: sleep_for(100us) otherwise rounds up to the
    // system clock granularity (~8-15ms), starving the poll loop.
    timeBeginPeriod(1);
#endif
    // Diagnostic: reset counters and record start time
    g_connStartTime = std::chrono::steady_clock::now();
    g_txPackets = 0; g_txBytes = 0;
    g_rxPackets = 0; g_rxBytes = 0;
    g_initialSent = false;
    g_handshakeCompleted = false;

    params_ = params;

    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=0.0ms InitClient: server=%s sni=%s insecure=%d\n",
                     params.remoteAddr.c_str(), params.serverName.c_str(),
                     params.insecureSkipVerify ? 1 : 0);
    }

    bool initOkClient = true;
    std::call_once(g_cryptoInitFlag, [&]() {
        if (ngtcp2_crypto_ossl_init() != 0) initOkClient = false;
    });
    if (!initOkClient) return false;

    // Create UDP socket and connect
    socket_ = std::make_unique<UdpSocket>();

    // Parse "host:port" from remoteAddr
    std::string connectHost = params.remoteAddr;
    uint16_t connectPort = params.remotePort;
    if (connectPort == 0) {
        // Try to extract port from "host:port" format
        auto lastColon = params.remoteAddr.rfind(':');
        if (lastColon != std::string::npos) {
            connectHost = params.remoteAddr.substr(0, lastColon);
            connectPort = static_cast<uint16_t>(
                std::atoi(params.remoteAddr.c_str() + lastColon + 1));
        }
    }

    if (!socket_->Connect(connectHost, connectPort, params.localBindAddr)) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms socket->Connect(%s:%u) FAILED\n",
                         ElapsedMs(), connectHost.c_str(), connectPort);
        }
        return false;
    }
    remoteAddrStr_ = params.remoteAddr;
    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms socket connected fd=%d to %s\n",
                     ElapsedMs(), socket_->GetFd(), remoteAddrStr_.c_str());
    }

    // Capture local/remote sockaddrs for ngtcp2_path.
    struct sockaddr_storage ss{};
    socklen_t sl = 0;
    if (socket_->RemoteSockaddr(&ss, &sl)) {
        remoteAddr_ = ss;
        remoteAddrLen_ = sl;
    }
    if (socket_->LocalSockaddr(&ss, &sl)) {
        localAddr_ = ss;
        localAddrLen_ = sl;
    }

    // Set up TLS context if not provided
    if (!params.sslCtx) {
        sslCtx_ = SSL_CTX_new(TLS_client_method());
        ownsSslCtx_ = true;
        if (!sslCtx_) return false;
        SSL_CTX_set_min_proto_version(sslCtx_, TLS1_3_VERSION);

        // ChromeParrot TLS fingerprint: configure Supported Groups, Signature
        // Algorithms, and Cipher Suites to match the official hy2-go ChromeParrot
        // behavior. These values come from quic-go chrome_client_hello.go.
        // Only applied when we create our own SSL_CTX (not caller-provided).
        if (!params.quicCfg.DisableChromeParrot) {
            // Supported Groups: matches Chrome's QUIC ClientHello.
            // X25519MLKEM768 (4588) is a hybrid post-quantum key exchange.
            // OpenSSL 3.5+ supports this group name.
            if (SSL_CTX_set1_groups_list(sslCtx_,
                    "X25519MLKEM768:X25519:P-256:P-384") != 1) {
                ERR_clear_error();
                // Fallback: if ML-KEM not supported, try without it.
                // This means the wire will show X25519:P-256:P-384 instead.
                SSL_CTX_set1_groups_list(sslCtx_, "X25519:P-256:P-384");
                ERR_clear_error();
            }

            // Signature Algorithms: matches Chrome's QUIC ClientHello.
            // No Ed25519 (Chrome omits it for QUIC).
            if (SSL_CTX_set1_sigalgs_list(sslCtx_,
                    "ECDSA+SHA256:"
                    "RSA-PSS+SHA256:"
                    "RSA+SHA256:"
                    "ECDSA+SHA384:"
                    "RSA-PSS+SHA384:"
                    "RSA+SHA384:"
                    "RSA-PSS+SHA512:"
                    "RSA+SHA512:"
                    "RSA+SHA1") != 1) {
                ERR_clear_error();
                // Non-fatal: keep OpenSSL defaults.
            }

            // TLS 1.3 Cipher Suites: matches Chrome's QUIC ClientHello.
            // No GREASE cipher suite (unlike TCP hello).
            if (SSL_CTX_set_ciphersuites(sslCtx_,
                    "TLS_AES_128_GCM_SHA256:"
                    "TLS_AES_256_GCM_SHA384:"
                    "TLS_CHACHA20_POLY1305_SHA256") != 1) {
                ERR_clear_error();
                // Non-fatal: keep OpenSSL defaults.
            }
        }

        // Load root CAs if provided; otherwise use system defaults.
        for (const auto& pem : params.rootCAsPEM) {
            BIO* bio = BIO_new_mem_buf(pem.data(),
                                       static_cast<int>(pem.size()));
            if (!bio) continue;
            STACK_OF(X509_INFO) * infos =
                PEM_X509_INFO_read_bio(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);
            if (!infos) continue;
            int count = sk_X509_INFO_num(infos);
            for (int i = 0; i < count; ++i) {
                X509_INFO* info = sk_X509_INFO_value(infos, i);
                if (info && info->x509) {
                    X509_STORE_add_cert(SSL_CTX_get_cert_store(sslCtx_),
                                        info->x509);
                }
            }
            sk_X509_INFO_pop_free(infos, X509_INFO_free);
        }
    } else {
        sslCtx_ = params.sslCtx;
        ownsSslCtx_ = false;
    }

    // Init TLS (creates ssl_, configures QUIC-TLS cbs)
    if (!InitTls()) return false;

    // Set up ngtcp2 callbacks. The packet-protection + TLS glue callbacks
    // come from libngtcp2_crypto (works with both quictls and ossl models).
    if (!InitCommonCallbacks()) return false;
    // Client-side TLS callbacks
    callbacks_.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks_.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks_.recv_retry = ngtcp2_crypto_recv_retry_cb;

    // Set up ngtcp2 settings
    const std::string ccCfg = params.quicCfg.CongestionControl;
    ngtcp2_settings_default(&settings_);
    settings_.cc_algo = SelectCcAlgo(ccCfg, NGTCP2_CC_ALGO_BBR);  // Config-selected CC; BBR by default (HY2_CC_ALGO overrides for A/B tests)
    settings_.initial_ts = NowTimestamp();
    // PMTUD must be off when ChromeParrot is active: ngtcp2's probe-based
    // discovery caps the validated path MTU at the largest probe size
    // (1232 with max_tx=1250), which shrinks the QUIC datagram capacity
    // below the protocol max of 1200B. The official Go client (quic-go
    // ChromeParrot) never probes below its 1250B packet size, so datagrams
    // of 1200B always fit.
    settings_.no_pmtud = params_.quicCfg.DisablePathMTUDiscovery
                             ? 1
                             : (!params_.quicCfg.DisableChromeParrot ? 1 : 0);
    // Without PMTUD, the per-path payload size stays at its initial
    // NGTCP2_MAX_UDP_PAYLOAD_SIZE (1200) unless shaping is disabled ��
    // which would silently cap every packet (and datagram) below the
    // configured size. Disable shaping so max_tx_udp_payload_size applies.
    if (settings_.no_pmtud) {
        settings_.no_tx_udp_payload_size_shaping = 1;
    }
    // HY2: ACK every packet immediately (see InitServer comment).
    settings_.ack_thresh = 1;
    if (std::getenv("HY2_QUIC_DEBUG")) {
        settings_.log_printf = Ngtcp2LogPrintf;
    }

    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG-SETTINGS] initial_ts=%llu (nanoseconds since epoch)\n",
                     (unsigned long long)settings_.initial_ts);
        std::fprintf(stderr, "[DIAG-SETTINGS] NowTimestamp=%llu\n",
                     (unsigned long long)NowTimestamp());
        std::fprintf(stderr, "[DIAG-SETTINGS] max_idle_timeout=%llu\n",
                     (unsigned long long)transportParams_.max_idle_timeout);
    }

    // ChromeParrot overrides for ngtcp2 settings (local transmit behavior).
    // These differ from transport parameters �� they affect what we SEND,
    // not what we advertise to the peer.
    if (!params_.quicCfg.DisableChromeParrot) {
        settings_.initial_pkt_num = 1;                       // Chrome starts at PN 1
    }
    // Payload cap applies to DATA packets; keeping it at 1350 instead of
    // 1250 cuts the packet count (and thus CPU) by ~8% at the same
    // throughput. Only the handshake fingerprint cares about 1250 and that
    // is driven by initial_pkt_num / padding, not by this cap.
    settings_.max_tx_udp_payload_size = 1452;  // IPv4/UDP max without fragmentation on a 1500 MTU path

    FillTransportParams(&transportParams_, params_.quicCfg, true,
                        params_.quicCfg.DisableChromeParrot);

    // Create the ngtcp2 connection
    // DCID must be >= NGTCP2_MIN_INITIAL_DCIDLEN (8 bytes) per ngtcp2 API.
    // SCID: when DisableChromeParrot=false (default), use zero-length SCID
    // to match the official hy2-go behavior where
    // tr.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}.
    ngtcp2_cid dcid{}, scid{};
    dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
    RAND_bytes(dcid.data, static_cast<int>(dcid.datalen));
    if (params_.quicCfg.DisableChromeParrot) {
        scid.datalen = 8;
        RAND_bytes(scid.data, static_cast<int>(scid.datalen));
    } else {
        // Zero-length SCID: matches Chrome fingerprint.
        // ngtcp2 encodes this as scid_len=0 in the Initial long header.
        scid.datalen = 0;
    }
    dcid_ = dcid;
    scid_ = scid;

    ngtcp2_path_storage ps;
    BuildPath(&ps);

    DBG("client: calling conn_client_new");
    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms ngtcp2_conn_client_new: proto=QUICv1\n", ElapsedMs());
    }
    int rv = ngtcp2_conn_client_new(&conn_, &dcid_, &scid_, &ps.path,
                                    NGTCP2_PROTO_VER_V1,
                                    &callbacks_, &settings_,
                                    &transportParams_, nullptr, this);
    if (rv != 0) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms ngtcp2_conn_client_new FAILED rv=%d\n",
                         ElapsedMs(), rv);
        }
        return false;
    }

    if (params_.quicCfg.HandshakeTimeout.ns > 0) {
        handshakeTimeout_ = std::chrono::milliseconds(params_.quicCfg.HandshakeTimeout.ns / 1000000);
    }
    // Declared send rate -> in-stack Brutal controller (see QuicConfig).
    if (settings_.cc_algo == NGTCP2_CC_ALGO_BRUTAL && params_.quicCfg.BrutalRate > 0) {
        ngtcp2_conn_set_brutal_rate(conn_, params_.quicCfg.BrutalRate);
    }
    // Keep the connection alive while the tunnel is idle.
    //
    // MaxIdleTimeout (30 s by default) has always been applied to the transport
    // parameters, but nothing ever reset that timer: ngtcp2 disables keep-alive
    // unless told otherwise (UINT64_MAX is its default), and KeepAlivePeriod was
    // parsed, defaulted to 10 s and range-checked in Config::VerifyAndFill()
    // and then never handed to the connection. So a tunnel that saw no traffic
    // for 30 s hit the idle timeout and closed - silently, since nobody is
    // watching for it. Client-side only, matching quic-go: the pings reset the
    // server's idle timer as well, so one side pinging is enough.
    if (params_.quicCfg.KeepAlivePeriod.ns > 0) {
        ngtcp2_conn_set_keep_alive_timeout(
            conn_,
            static_cast<ngtcp2_duration>(params_.quicCfg.KeepAlivePeriod.Milliseconds()) *
                NGTCP2_MILLISECONDS);
    }

    DBG("client: conn created");
    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms ngtcp2 conn created, creating ossl ctx\n", ElapsedMs());
        ngtcp2_tstamp exp = ngtcp2_conn_get_expiry2(conn_);
        ngtcp2_tstamp now = NowTimestamp();
        std::fprintf(stderr, "[DIAG-CONN] expiry=%llu now=%llu delta=%lld ns (%.1f ms)\n",
                     (unsigned long long)exp, (unsigned long long)now,
                     (long long)(exp - now), (double)(exp - now) / 1000000.0);
        std::fprintf(stderr, "[DIAG-CONN] settings.initial_ts=%llu\n",
                     (unsigned long long)settings_.initial_ts);
        std::fprintf(stderr, "[DIAG-CONN] transportParams.max_idle_timeout=%llu ns (%.1f ms)\n",
                     (unsigned long long)transportParams_.max_idle_timeout,
                     (double)transportParams_.max_idle_timeout / 1000000.0);
    }
    // 1. create per-connection ossl ctx holding the SSL*
    if (ngtcp2_crypto_ossl_ctx_new(&osslCtx_, ssl_) != 0) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms ngtcp2_crypto_ossl_ctx_new FAILED\n", ElapsedMs());
        }
        return false;
    }
    // 2. register it as the TLS native handle on the ngtcp2 conn
    ngtcp2_conn_set_tls_native_handle(conn_, osslCtx_);
    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms ossl ctx + native handle set OK\n", ElapsedMs());
    }
    // 3. point SSL app-data at this conn so the crypto layer can find it
    connRef_.get_conn = [](ngtcp2_crypto_conn_ref* ref) -> ngtcp2_conn* {
        auto* self = static_cast<Ngtcp2Connection*>(ref->user_data);
        return self ? self->conn_ : nullptr;
    };
    connRef_.user_data = this;
    SSL_set_app_data(ssl_, &connRef_);

    InitClientWakePipe();

    return true;
}

void Ngtcp2Connection::InitClientWakePipe() {
#ifdef _WIN32
    clientWakeRead_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    clientWakeWrite_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (clientWakeRead_ == INVALID_SOCKET || clientWakeWrite_ == INVALID_SOCKET) {
        if (clientWakeRead_ != INVALID_SOCKET) { closesocket(clientWakeRead_); clientWakeRead_ = INVALID_SOCKET; }
        if (clientWakeWrite_ != INVALID_SOCKET) { closesocket(clientWakeWrite_); clientWakeWrite_ = INVALID_SOCKET; }
        return;
    }
    u_long nonBlocking = 1;
    ioctlsocket(clientWakeRead_, FIONBIO, &nonBlocking);
    ioctlsocket(clientWakeWrite_, FIONBIO, &nonBlocking);
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    int len = sizeof(addr);
    bind(clientWakeRead_, reinterpret_cast<struct sockaddr*>(&addr), len);
    getsockname(clientWakeRead_, reinterpret_cast<struct sockaddr*>(&addr), &len);
    connect(clientWakeWrite_, reinterpret_cast<struct sockaddr*>(&addr), len);
#else
    if (pipe(&clientWakeRead_) != 0) {
        clientWakeRead_ = -1;
        clientWakeWrite_ = -1;
        return;
    }
    fcntl(clientWakeRead_, F_SETFL, O_NONBLOCK);
    fcntl(clientWakeWrite_, F_SETFL, O_NONBLOCK);
#endif
}

void Ngtcp2Connection::CloseClientWakePipe() {
#ifdef _WIN32
    if (clientWakeRead_ != INVALID_SOCKET) { closesocket(clientWakeRead_); clientWakeRead_ = INVALID_SOCKET; }
    if (clientWakeWrite_ != INVALID_SOCKET) { closesocket(clientWakeWrite_); clientWakeWrite_ = INVALID_SOCKET; }
#else
    if (clientWakeRead_ >= 0) { close(clientWakeRead_); clientWakeRead_ = -1; }
    if (clientWakeWrite_ >= 0) { close(clientWakeWrite_); clientWakeWrite_ = -1; }
#endif
}

void Ngtcp2Connection::StartInternalLoop() {
    if (loopRunning_.exchange(true)) return;
    stopLoop_ = false;
    auto self = shared_from_this();
    loopThread_ = std::thread([self] { self->InternalLoop(); });
}

void Ngtcp2Connection::StopInternalLoop() {
    stopLoop_ = true;
    // Unblock the poll()/WSAPoll() the loop is blocked in so it can
    // observe stopLoop_ immediately instead of waiting for the next
    // event or timer expiry.
    WakeUp();
    if (loopThread_.joinable()) {
        if (loopThread_.get_id() == std::this_thread::get_id()) {
            // This destructor runs *on* the internal loop thread when the loop
            // lambda held the last reference (very common: the pool drops its
            // shared_ptr while a connection is being torn down). Detach, or
            // ~std::thread() finds the handle still joinable and calls
            // std::terminate -> abort() -> __fastfail(FAST_FAIL_FATAL_APP_EXIT)
            // = 0xC0000409 in ucrtbase (the crash this fixes).
            loopThread_.detach();
        } else {
            loopThread_.join();
        }
    }
}

void Ngtcp2Connection::InternalLoop() {
    uint8_t buf[65536];
#ifdef _WIN32
    // 1 ms timer resolution + a slightly raised priority: the sender's
    // congestion window is derived from measured RTT, which on Windows is
    // dominated by thread wake latency. Both keep wake-ups prompt.
    timeBeginPeriod(1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif
    if (QuicDebugEnabled()) std::fprintf(stderr, "[dbg] client loop started fd=%d\n", socket_ ? socket_->GetFd() : -1);

    // CRITICAL: Drive the state machine immediately to flush the Initial packet.
    Drive();

    auto diagPrintTime = std::chrono::steady_clock::now();
    static const bool diagEnabled = std::getenv("HY2_BW_DIAG") != nullptr;
    while (!stopLoop_ && !closed_) {
        if (Hy2DiagEnabled()) diag_.loopCount.fetch_add(1, std::memory_order_relaxed);

        // Periodic diagnostic print (every 1 second when HY2_BW_DIAG=1)
        if (diagEnabled) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - diagPrintTime).count();
            if (elapsed >= 1) {
                diag_.Print("EVENTLOOP");
                diagPrintTime = now;
            }
        }
        if (Hy2DiagEnabled()) ConnHeartbeat("client");

        // Event-driven wait: block until the socket has data, the wake pipe
        // signals a Stream::Write, or the nearest QUIC timer expires.
        // There is NO fixed-cadence sleep: packets leave the moment the
        // application submits them, so ngtcp2's RTT samples measure the
        // network instead of our scheduler (see ARCHITECTURE_REDESIGN.md).
        int fd = socket_ ? socket_->GetFd() : -1;
#ifdef _WIN32
        int wakeFd = (clientWakeRead_ != INVALID_SOCKET)
                         ? static_cast<int>(clientWakeRead_) : -1;
#else
        int wakeFd = clientWakeRead_;
#endif
            IoWaitResult res;
        {
            static std::atomic<int64_t> gWaitNsAcc{0};
            const auto w0 = std::chrono::steady_clock::now();
            // Cap the wait at 100 ms. GetExpiry() returns time_point::max() when
            // ngtcp2 has no timer armed - and without the pacer it sometimes arms none
            // even while data waits to be sent, so the loop slept until a packet
            // arrived (download fine, upload dead: nothing ever woke it).
            {
                const auto cap = std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
                const auto expiry = GetExpiry();
                res = IoWait(fd, wakeFd, expiry < cap ? expiry : cap);
            }
            if (Hy2DiagEnabled()) {
                gWaitNsAcc.fetch_add(std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - w0).count());
                static std::mutex lrepMu; static int64_t lNextMs = 0;
                const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                if (nowMs >= lNextMs) {
                    std::lock_guard<std::mutex> rl(lrepMu);
                    if (nowMs >= lNextMs) {
                        std::fprintf(stderr, "[loop] 1s wait_ms=%lld (blocked waiting for events)\n",
                                     (long long)(gWaitNsAcc.exchange(0) / 1000000));
                        std::fflush(stderr);
                        lNextMs = nowMs + 1000;
                    }
                }
            }
        }
        if (res == IoWaitResult::kError) break;
        if (stopLoop_ || closed_) break;

        // Drain the wake signal (application thread wrote to a stream).
#ifdef _WIN32
        if (clientWakeRead_ != INVALID_SOCKET) {
            char tmp[8];
            while (recv(clientWakeRead_, tmp, sizeof(tmp), 0) > 0) {}
        }
#else
        if (clientWakeRead_ >= 0) {
            char tmp[8];
            while (read(clientWakeRead_, tmp, sizeof(tmp)) > 0) {}
        }
#endif

        // Drain all pending datagrams and feed them to ngtcp2 under a
        // SINGLE op-lock acquisition (one lock per burst instead of one
        // lock pair per datagram).
        bool gotAny = false;
        BeginOpBlocking();
        {
            struct OpGuard {
                Ngtcp2Connection* c;
                ~OpGuard() { c->EndOp(); }
            } guard{this};
            for (;;) {
                int n = socket_->Recv(buf, sizeof(buf));
                if (n <= 0) break;
                gotAny = true;
                if (Hy2DiagEnabled()) {
                    diag_.recvPackets.fetch_add(1, std::memory_order_relaxed);
                }
                if (!ReadPacketLocked(buf, static_cast<size_t>(n))) break;
            }
        }
        // Wake readers once for the whole batch (per-packet notifies made
        // both threads pay a condvar round trip per datagram).
        FlushReadNotifyBatch();
        if (gotAny) {
            // Owes ACKs (and possibly retransmits): make sure Drive() runs
            // below even when no application data was written meanwhile.
            MarkTxPending();
        }
        if (stopLoop_ || closed_) break;

        // QUIC timer due: PTO, keepalive, idle timeout, ack delay. The
        // deadline we passed to IoWait() guarantees this fires on time.
        if (res == IoWaitResult::kTimeout || TimerOverdue()) {
            OnTimeout();
        }

        // Flush: stream data queued by app threads, ACKs owed after recv,
        // and retransmits scheduled by handle_expiry. Drive() bursts until
        // cwnd is exhausted (its internal loop keeps calling
        // ngtcp2_conn_writev_stream until the CC window is used up).
        // Always drive: ACK/window updates owed after a receive, retransmits
        // scheduled by the timer, and app writes all flush here. The old
        // ConsumeTxPending() gate could miss the rx/timer paths (they do not
        // always set the app-write flag first), which stalled the peer's ACK
        // clock.
        if (Hy2DiagEnabled()) {
            auto dStart = std::chrono::steady_clock::now();
            Drive();
            auto dEnd = std::chrono::steady_clock::now();
            diag_.driveCalls.fetch_add(1, std::memory_order_relaxed);
            diag_.driveNs.fetch_add(
                std::chrono::duration_cast<std::chrono::nanoseconds>(dEnd - dStart).count(),
                std::memory_order_relaxed);
        } else {
            Drive();
        }

        if (socket_) socket_->DrainTxQueue();
    }

    // The loop has stopped, so this connection will never carry another byte.
    // Release everything parked on it here rather than relying on an owner to
    // call CloseWithError(): when the connection dies on its own - the idle
    // timeout, a peer CONNECTION_CLOSE, a failed handle_expiry - nothing else is
    // guaranteed to come along, and a reader parked on a dead connection stays
    // parked forever. That is what used to hang the engine's teardown join.
    WakeAllWaiters();
}

// ---------------------------------------------------------------------------
// IQuicConnection interface
// ---------------------------------------------------------------------------

std::shared_ptr<IQuicStream> Ngtcp2Connection::OpenStream() {
    if (closed_) throw hy2::Error("connection closed");

    // Wait for handshake to complete (stream IDs unavailable before that)
    {
        hy2::diag::LockTimer _hy2lt_1225("ngtcp2_connection:1225 mu_");
          std::unique_lock<std::mutex> lk(mu_);
          _hy2lt_1225.done();
        bool ok = handshakeCv_.wait_for(lk, handshakeTimeout_,
            [this] { return handshakeComplete_.load(std::memory_order_acquire) || closed_.load(); });
        if (!ok || (!handshakeComplete_ && closed_))
            throw hy2::Error("timeout waiting for QUIC handshake");
    }
    if (closed_) throw hy2::Error("connection closed during handshake");

    // Serialize with the event-loop threads: no ngtcp2 call may run
    // concurrently with read/write/expiry on the same connection.
    BeginOpBlocking();
    int64_t streamId = 0;
    int rv;
    {
        struct OpGuard {
            Ngtcp2Connection* c;
            ~OpGuard() { c->EndOp(); }
        } guard{this};
        rv = ngtcp2_conn_open_bidi_stream(conn_, &streamId, nullptr);
    }
    TTRACE(9, rv);
    if (rv != 0) {
        if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
            throw hy2::StreamLimitReachedError();
        }
        throw hy2::Error("failed to open stream: " + std::string(ngtcp2_strerror(rv)));
    }

    auto stream = std::shared_ptr<Ngtcp2Stream>(
        new Ngtcp2Stream(shared_from_this(), streamId));
    {
        hy2::diag::LockTimer _hy2lt_1255("ngtcp2_connection:1255 mu_");
          std::lock_guard<std::mutex> lk(mu_);
          _hy2lt_1255.done();
        streams_[streamId] = stream;
    }
    return stream;
}

std::shared_ptr<IQuicStream> Ngtcp2Connection::AcceptStream() {
    hy2::diag::LockTimer _hy2lt_1262("ngtcp2_connection:1262 acceptMu_");
      std::unique_lock<std::mutex> lk(acceptMu_);
      _hy2lt_1262.done();
    acceptCv_.wait(lk, [this] {
        return !pendingAccepts_.empty() || closed_.load();
    });
    if (pendingAccepts_.empty()) throw hy2::Error("connection closed");
    auto s = std::move(pendingAccepts_.front());
    pendingAccepts_.erase(pendingAccepts_.begin());
    return s;
}

std::shared_ptr<IQuicStream> Ngtcp2Connection::AcceptStreamFor(int timeoutMs) {
    hy2::diag::LockTimer _hy2lt_1273("ngtcp2_connection:1273 acceptMu_");
      std::unique_lock<std::mutex> lk(acceptMu_);
      _hy2lt_1273.done();
    DBG_LOG("[AcceptStreamFor] waiting", "timeout_ms", timeoutMs, "pending", pendingAccepts_.size());
    acceptCv_.wait_for(lk, std::chrono::milliseconds(timeoutMs), [this] {
        return !pendingAccepts_.empty() || closed_.load();
    });
    DBG_LOG("[AcceptStreamFor] woke up", "pending", pendingAccepts_.size(), "closed", closed_.load());
    if (pendingAccepts_.empty()) return nullptr;
    auto s = std::move(pendingAccepts_.front());
    pendingAccepts_.erase(pendingAccepts_.begin());
    return s;
}

std::shared_ptr<IQuicStream> Ngtcp2Connection::AcceptUniStream() {
    hy2::diag::LockTimer _hy2lt_1286("ngtcp2_connection:1286 uniAcceptMu_");
      std::unique_lock<std::mutex> lk(uniAcceptMu_);
      _hy2lt_1286.done();
    uniAcceptCv_.wait(lk, [this] { return !pendingUniAccepts_.empty() || closed_.load(); });
    if (pendingUniAccepts_.empty()) return nullptr;
    auto s = std::move(pendingUniAccepts_.front());
    pendingUniAccepts_.erase(pendingUniAccepts_.begin());
    return s;
}

std::shared_ptr<IQuicStream> Ngtcp2Connection::OpenUniStream() {
    if (closed_) throw hy2::Error("connection closed");

    // Wait for handshake to complete (stream IDs unavailable before that)
    {
        hy2::diag::LockTimer _hy2lt_1299("ngtcp2_connection:1299 mu_");
          std::unique_lock<std::mutex> lk(mu_);
          _hy2lt_1299.done();
        bool ok = handshakeCv_.wait_for(lk, handshakeTimeout_,
            [this] { return handshakeComplete_.load(std::memory_order_acquire) || closed_.load(); });
        if (!ok || (!handshakeComplete_ && closed_))
            throw hy2::Error("timeout waiting for QUIC handshake");
    }
    if (closed_) throw hy2::Error("connection closed during handshake");

    BeginOpBlocking();
    int64_t streamId = 0;
    int rv;
    {
        struct OpGuard {
            Ngtcp2Connection* c;
            ~OpGuard() { c->EndOp(); }
        } guard{this};
        rv = ngtcp2_conn_open_uni_stream(conn_, &streamId, nullptr);
    }
    TTRACE(10, rv);
    if (rv != 0) {
        throw hy2::Error("failed to open uni stream: " + std::string(ngtcp2_strerror(rv)));
    }

    auto stream = std::shared_ptr<Ngtcp2Stream>(
        new Ngtcp2Stream(shared_from_this(), streamId));
    {
        hy2::diag::LockTimer _hy2lt_1324("ngtcp2_connection:1324 mu_");
          std::lock_guard<std::mutex> lk(mu_);
          _hy2lt_1324.done();
        streams_[streamId] = stream;
    }
    return stream;
}

void Ngtcp2Connection::SendDatagram(const uint8_t* p, size_t n) {
    if (closed_) throw hy2::Error("connection closed");

    // Effective capacity: the peer's advertised max_datagram_frame_size
    // bounds the DATAGRAM frame payload, but the frame itself carries a
    // 1-byte type + varint length header �� quic-go reserves exactly these
    // 3 bytes (DatagramFrame.MaxDataLen) and so does ngtcp2. Bound the
    // result by what fits into one path-MTU packet (short header + CID +
    // PN + AEAD overhead).
    const ngtcp2_transport_params* rp =
        ngtcp2_conn_get_remote_transport_params(conn_);
    if (!rp || rp->max_datagram_frame_size == 0) {
        throw hy2::Error("peer does not support QUIC datagrams");
    }
    size_t cap = static_cast<size_t>(rp->max_datagram_frame_size);
    constexpr size_t kDatagramFrameHdr = 3; // frame type + 2-byte varint length
    cap = cap > kDatagramFrameHdr ? cap - kDatagramFrameHdr : 0;
    size_t pathCap = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn_);
    constexpr size_t kDatagramPktOverhead = 40;
    if (pathCap > kDatagramPktOverhead) pathCap -= kDatagramPktOverhead;
    if (cap > pathCap) cap = pathCap;

    if (n > cap) throw hy2::DatagramTooLargeError(static_cast<int64_t>(cap));

    // Diagnostics are gated on the cached flag: the default path must not pay
    // atomic RMWs or clock reads per datagram (same rule as SendPacket).
    const bool diag = Hy2DiagEnabled();
    std::chrono::steady_clock::time_point lockWaitStart;
    if (diag) {
        diag_.dgramTxCalls.fetch_add(1, std::memory_order_relaxed);
        lockWaitStart = std::chrono::steady_clock::now();
    }
    BeginOpBlocking();
    if (diag) {
        const auto lockHoldStart = std::chrono::steady_clock::now();
        diag_.dgramTxLockWaitNs.fetch_add(
            std::chrono::duration_cast<std::chrono::nanoseconds>(lockHoldStart - lockWaitStart).count(),
            std::memory_order_relaxed);
    }

    uint8_t buf[1500];
    ngtcp2_path* path = GetPath();
    ngtcp2_pkt_info pi{};
    ngtcp2_vec vec{const_cast<uint8_t*>(p), n};
    int accepted = 0;
    ngtcp2_ssize rv;
    {
        struct OpGuard {
            Ngtcp2Connection* c;
            bool timing;
            std::chrono::steady_clock::time_point start;
            ~OpGuard() {
                if (timing) {
                    auto end = std::chrono::steady_clock::now();
                    c->diag_.dgramTxLockHoldNs.fetch_add(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count(),
                        std::memory_order_relaxed);
                }
                c->EndOp();
            }
        } guard{this, diag,
                diag ? std::chrono::steady_clock::now()
                     : std::chrono::steady_clock::time_point{}};
        rv = ngtcp2_conn_writev_datagram(
            conn_, path, &pi, buf, sizeof(buf), &accepted, 0, 0,
            &vec, 1, NowTimestamp());
        if (rv > 0) {
            SendPacket(buf, static_cast<size_t>(rv));
        }
        if (!accepted && rv >= 0) {
            // ACK/PING frames consumed the packet budget (writev_datagram
            // refuses the DATAGRAM frame when it does not fit next to
            // them). Retry once in a fresh packet: the frames were flushed
            // by the call above, so the datagram now has full room.
            accepted = 0;
            rv = ngtcp2_conn_writev_datagram(
                conn_, path, &pi, buf, sizeof(buf), &accepted, 0, 0,
                &vec, 1, NowTimestamp());
            if (rv > 0) {
                SendPacket(buf, static_cast<size_t>(rv));
            }
        }
    }
    if (rv < 0) {
        if (diag) diag_.dgramTxRvNeg.fetch_add(1, std::memory_order_relaxed);
        throw hy2::Error("send datagram failed: " + std::to_string(static_cast<int>(rv)));
    }
    if (rv == 0) {
        if (diag) diag_.dgramTxRv0.fetch_add(1, std::memory_order_relaxed);
        throw hy2::Error("datagram not accepted (connection not ready or buffer full)");
    }
    if (!accepted) {
        if (diag) diag_.dgramTxAccepted0.fetch_add(1, std::memory_order_relaxed);
        throw hy2::Error("datagram not accepted (accepted=0)");
    }
    if (diag) diag_.dgramTxSuccess.fetch_add(1, std::memory_order_relaxed);
}

std::vector<uint8_t> Ngtcp2Connection::ReceiveDatagram() {
    hy2::diag::LockTimer _hy2lt_1417("ngtcp2_connection:1417 datagramMu_");
      std::unique_lock<std::mutex> lk(datagramMu_);
      _hy2lt_1417.done();
    datagramCv_.wait(lk, [this] { return !recvDatagrams_.empty() || closed_.load(); });
    if (recvDatagrams_.empty()) throw hy2::Error("connection closed");
    std::vector<uint8_t> d = std::move(recvDatagrams_.front());
    recvDatagrams_.pop_front();
    return d;
}

// Consumption-driven receive-window credit (see the header comment).
void Ngtcp2Connection::ExtendReadCredit(int64_t stream_id, uint64_t credit) {
    if (credit == 0 || !conn_ || closed_) return;

    BeginOpBlocking();
    {
        struct OpGuard {
            Ngtcp2Connection* c;
            ~OpGuard() { c->EndOp(); }
        } guard{this};
        // Connection-level window: keeps the aggregate bound tied to what the
        // application actually consumed (a stalled reader cannot accumulate
        // connection window for other streams).
        ngtcp2_conn_extend_max_offset(conn_, credit);
        // Stream-level window. Returns 0 (no-op) when the stream is already
        // gone from ngtcp2's map, so an app holding a closed stream is safe.
        (void)ngtcp2_conn_extend_max_stream_offset(conn_, stream_id, credit);
    }
    // The MAX_STREAM_DATA/MAX_DATA update is owed to the peer now; wake the
    // IO loop so it is emitted with the next packet (ACK-clocked).
    WakeUpOnData();
}

void Ngtcp2Connection::CloseWithError(uint64_t errorCode, const std::string& reason) {
    // Deliberately NOT an early return when closed_ is already set.
    //
    // A connection can end its own life: the QUIC idle timeout and a peer
    // CONNECTION_CLOSE both set closed_ from inside the IO loop. This call is
    // the only thing that releases the threads parked on the connection, so
    // returning early here left every stream read, accept wait and datagram
    // consumer blocked forever - the engine's teardown join then never returned
    // and the UI sat on "disconnecting" with no way out. WakeAllWaiters() is
    // idempotent, so repeating it costs a few notifies.
    closed_.store(true);
    WakeAllWaiters();

    // Diagnostic: connection summary
    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms CloseWithError: code=%llu reason=%s hs=%d tx=%d/%d rx=%d/%d\n",
                     ElapsedMs(), (unsigned long long)errorCode, reason.c_str(),
                     g_handshakeCompleted.load() ? 1 : 0,
                     g_txPackets.load(), g_txBytes.load(), g_rxPackets.load(), g_rxBytes.load());
    }

    if (conn_) {
        BeginOpBlocking();
        uint8_t buf[1500];
        ngtcp2_path* path = GetPath();
        ngtcp2_pkt_info pi{};
        {
            struct OpGuard {
                Ngtcp2Connection* c;
                ~OpGuard() { c->EndOp(); }
            } guard{this};

            ngtcp2_ccerr ccerr;
            ngtcp2_ccerr_default(&ccerr);
            ngtcp2_ccerr_set_application_error(&ccerr, errorCode,
                                               reinterpret_cast<const uint8_t*>(reason.data()),
                                               reason.size());
            ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
                conn_, path, &pi, buf, sizeof(buf), &ccerr, NowTimestamp());
            if (nwrite > 0) {
                SendPacket(buf, static_cast<size_t>(nwrite));
            }
        }
        // Give the close packet a moment to leave before tearing down.
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (socket_) socket_->Close();
}

std::string Ngtcp2Connection::LocalAddr() const {
    return socket_ ? socket_->LocalAddr() : "";
}

std::string Ngtcp2Connection::RemoteAddr() const {
    return remoteAddrStr_;
}

void Ngtcp2Connection::SetCongestionControl(std::shared_ptr<cc::CongestionControl> cc) {
    IQuicConnection::SetCongestionControl(std::move(cc));
    if (congestion_) {
        congestion_->SetRTTStatsProvider(&rttStats_);
        // A non-zero negotiated rate means the fixed-rate sender was selected
        // after the handshake. The server only learns the client's declared
        // receive rate in the auth request, i.e. after the connection was
        // created with the configured default controller, so switch the
        // in-stack algorithm to Brutal here (ngtcp2_conn_set_brutal_rate does
        // the switch + arming; it used to be a no-op for non-Brutal conns,
        // which silently left the server on BBR and the declared rate
        // unenforced).
        if (conn_ && congestion_->BrutalRate() > 0) {
            ngtcp2_conn_set_brutal_rate(conn_, congestion_->BrutalRate());
            settings_.cc_algo = NGTCP2_CC_ALGO_BRUTAL;
        }
    }
}

// ---------------------------------------------------------------------------
// Driving the state machine
// ---------------------------------------------------------------------------

void Ngtcp2Connection::WakePipeWrite() {
#ifdef _WIN32
    if (clientWakeWrite_ != INVALID_SOCKET) {
        uint64_t val = 1;
        send(clientWakeWrite_, reinterpret_cast<const char*>(&val), sizeof(val), 0);
        return;
    }
    if (!wakeWrite_) return;
    if (*wakeWrite_ == INVALID_SOCKET) return;
    uint64_t val = 1;
    send(*wakeWrite_, (const char*)&val, sizeof(val), 0);
#else
    if (clientWakeWrite_ >= 0) {
        uint64_t val = 1;
        [[maybe_unused]] ssize_t n = write(clientWakeWrite_, &val, sizeof(val));
        return;
    }
    if (!wakeWrite_) return;
    if (*wakeWrite_ < 0) return;
    uint64_t val = 1;
    [[maybe_unused]] ssize_t n = write(*wakeWrite_, &val, sizeof(val));
#endif
}

void Ngtcp2Connection::WakeUp() {
    // Unconditional wake: close/stop paths must always interrupt the
    // blocked poll() even if the tx-pending flag is already set.
    MarkTxPending();
    if (serverLoopRunning_.load(std::memory_order_relaxed)) {
        rxCv_.notify_all();
        return;
    }
    WakePipeWrite();
}

void Ngtcp2Connection::WakeUpOnData() {
    // Edge-triggered: only wake on a false->true transition of the
    // tx-pending flag. Repeated Write() calls inside one send burst
    // therefore cost one atomic exchange instead of one syscall + one
    // redundant poll() wakeup each.
    // Always wake the loop: the wake pipe's send is non-blocking and can fail,
    // and since the tx-pending flag is an edge trigger that one lost wake used to
    // park the loop until a PTO timer (seconds) - uploads then crawled while
    // download kept working. One extra non-blocking send per Write is cheap.
    MarkTxPendingIfNotSet();
    if (serverLoopRunning_.load(std::memory_order_relaxed)) {
        rxCv_.notify_all();
        return;
    }
    WakePipeWrite();
}

void Ngtcp2Connection::Drive() {
    if (QuicDebugEnabled()) {
        std::fprintf(stderr, "[DIAG] t=%.1fms Drive: enter conn_=%p closed_=%d\n",
                     ElapsedMs(), (void*)conn_, (int)closed_.load());
    }
    if (!conn_ || closed_) return;

    // Blocking acquire: callers (stream Write/Close) must not be skipped,
    // otherwise queued data/FIN would sit until an unrelated event flushes.
    auto dOpStart = std::chrono::steady_clock::now();
    BeginOpBlocking();
    auto dLocked = std::chrono::steady_clock::now();

    struct DriveGuard {
        Ngtcp2Connection* c;
        ~DriveGuard() { c->EndOp(); }
    } guard{this};

    // Destroy deferred streams outside any ngtcp2 callback context.
    {
        std::vector<std::shared_ptr<Ngtcp2Stream>> zombies;
        {
            hy2::diag::LockTimer _hy2lt_1564("ngtcp2_connection:1564 mu_");
              std::lock_guard<std::mutex> lk(mu_);
              _hy2lt_1564.done();
            zombies.swap(zombieStreams_);
        }
    }

    uint8_t buf[1500];
    // One-packet scratch: ngtcp2 consumes at most one packet's payload per
    // writev_stream call, so copying a whole 8KB window per packet was ~7x
    // wasted memory traffic (Drive burned >100% of a core in bwtest).
    uint8_t dataCopy[1408];
    ngtcp2_path* path = GetPath();
    ngtcp2_pkt_info pi{};

    // Finish any half-built packet: keep calling until the API stops
    // answering WRITE_MORE (each call appends/flushes).
    auto FinalizePpe = [&]() {
        // IMPORTANT: Do NOT use WRITE_MORE here. The purpose of FinalizePpe
        // is to flush any half-built packet (e.g., a pending FIN frame after
        // the write loop ends). Using WRITE_MORE tells ngtcp2 "I'll add more
        // data" which prevents it from finalizing the packet �� causing the
        // FIN (and any trailing data) to be silently lost.
        for (int i = 0; i < 16; ++i) {
            ngtcp2_ssize n = ngtcp2_conn_writev_stream(
                conn_, path, &pi, buf, sizeof(buf),
                nullptr, 0, -1,
                nullptr, 0, NowTimestamp());
            TTRACE(6, n);
            if (QuicDebugEnabled()) {
                std::fprintf(stderr, "[DIAG] t=%.1fms FinalizePpe[%d]: writev_stream n=%lld\n",
                             ElapsedMs(), i, (long long)n);
            }
            if (n == NGTCP2_ERR_WRITE_MORE) continue;
            if (n > 0) SendPacket(buf, static_cast<size_t>(n));
            return;
        }
    };

    bool ppeMaybePending = false;
    auto dLoopStart = std::chrono::steady_clock::now();
    auto dLoopEnd = dLoopStart;
    auto dWvNs = 0LL;
    // Cached busy stream: while one stream has data, keep feeding it
    // without re-entering PickWritableStreamLocked() (which scans the
    // stream map and takes mu_) for every single packet.
    std::shared_ptr<Ngtcp2Stream> cur;
    for (;;) {
        // Zero-copy peek into the stream's front chunk (no memcpy, one
        // short lock). The pointer stays valid across the ngtcp2 call:
        // app threads only append at the tail of pre-reserved chunks.
        size_t datalen = 0;
        bool fin = false;
        const uint8_t* dataPtr = nullptr;

        if (!cur) {
            hy2::diag::LockTimer _hy2lt_1618("ngtcp2_connection:1618 mu_");
              std::lock_guard<std::mutex> lk(mu_);
              _hy2lt_1618.done();
            Ngtcp2Stream* s = PickWritableStreamLocked();
            if (s) {
                auto it = streams_.find(s->StreamID());
                if (it != streams_.end()) cur = it->second;
            }
            if (!cur) {
                dLoopEnd = std::chrono::steady_clock::now();
                if (QuicDebugEnabled()) {
                    std::fprintf(stderr, "[DIAG] t=%.1fms Drive: no writable streams\n", ElapsedMs());
                }
                // No more app data. Always finish with no-stream calls: this
                // flushes a half-built packet (after WRITE_MORE) or emits a
                // handshake/ack-only packet if one is due.
                if (QuicDebugEnabled()) {
                    std::fprintf(stderr, "[DIAG] t=%.1fms Drive: no streams, calling FinalizePpe\n",
                                 ElapsedMs());
                }
                FinalizePpe();
                break;
            }
        }

        // Always peek AFTER selection so the first iteration for a newly
        // picked stream carries real data (a zero-length WRITE_MORE call
        // would stall the burst).
        dataPtr = cur->PeekPendingWrite(&datalen, &fin);
        if (!dataPtr && !fin) {
            cur.reset(); // drained between selection and peek: pick another
            continue;
        }

        std::shared_ptr<Ngtcp2Stream>& sptr = cur;
        const int64_t stream_id = static_cast<int64_t>(sptr->StreamID());
        ngtcp2_vec datav{const_cast<uint8_t*>(dataPtr ? dataPtr : dataCopy), datalen};
        uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
        bool isPureFin = false;
        if (fin && datalen == 0) {
            // Pure FIN case: all data consumed, only FIN remains.
            // Send FIN as a separate dedicated packet (no WRITE_MORE).
            flags = NGTCP2_WRITE_STREAM_FLAG_FIN;
            isPureFin = true;
        }
        // Data chunks always use WRITE_MORE. FIN is never attached to data
        // packets �� it is sent as a separate pure-FIN packet after all data.

        // Refresh ts every iteration - ngtcp2 requires monotonic timestamps
        // and other entry points may have advanced last_ts meanwhile.
        ngtcp2_tstamp ts = NowTimestamp();
        ngtcp2_ssize wdatalen = 0;
        std::chrono::steady_clock::time_point dWvStart;
        if (Hy2DiagEnabled()) dWvStart = std::chrono::steady_clock::now();
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
            conn_, path, &pi, buf, sizeof(buf),
            &wdatalen, flags, stream_id, &datav, 1, ts);
        if (Hy2DiagEnabled()) {
            dWvNs += std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - dWvStart).count();
        }

        if (nwrite == 0) {
            dLoopEnd = std::chrono::steady_clock::now();
            g_driveRv0.fetch_add(1, std::memory_order_relaxed);
            DBG_LOG("[Drive] ngtcp2 returned 0 (congestion/flow-control blocked), stream_id", stream_id);
            if (QuicDebugEnabled() || Hy2DiagEnabled()) {
                ngtcp2_tstamp e = ngtcp2_conn_get_expiry2(conn_);
                ngtcp2_conn_info ci;
                ngtcp2_conn_get_conn_info(conn_, &ci);
                std::fprintf(stderr,
                             "[dbg] Drive rv=0 sid=%lld datalen=%zu cwnd=%llu inflight=%llu "
                             "expiry_delta_ms=%lld\n",
                             (long long)stream_id, datalen,
                             (unsigned long long)ci.cwnd,
                             (unsigned long long)ci.bytes_in_flight,
                             (long long)((int64_t)e - (int64_t)NowTimestamp()) / 1000000);
                std::fflush(stderr);
            }
            break;  // congestion/flow-control blocked
        }
        if (QuicDebugEnabled()) {
            std::fprintf(stderr,
                "[dbg] drive stream: sid=%llu datalen=%zu fin=%d rv=%lld wdatalen=%lld pend=%d\n",
                (unsigned long long)stream_id, datalen, (int)fin,
                (long long)nwrite, (long long)wdatalen, (int)ppeMaybePending);
        }
        TTRACE(3, nwrite);
        if (QuicDebugEnabled() && nwrite == 0) {
            ngtcp2_tstamp e = ngtcp2_conn_get_expiry2(conn_);
            std::fprintf(stderr, "[dbg] rv=0 cwnd_left=%llu inflight=%llu expiry_delta_ms=%lld\n",
                         (unsigned long long)ngtcp2_conn_get_cwnd_left2(conn_),
                         (unsigned long long)cinfo2_.bytes_in_flight,
                         (long long)((int64_t)e - (int64_t)NowTimestamp()) / 1000000);
        }

        if (nwrite == NGTCP2_ERR_WRITE_MORE) {
            TTRACE(4, wdatalen);
            if (wdatalen > 0 && sptr) {
                sptr->AdvanceWrite(static_cast<size_t>(wdatalen));
            }
            // NOTE: Do NOT call ClearFinPending() here when the FIN
            // flag is set. ERR_WRITE_MORE means ngtcp2 buffered the
            // FIN frame into the current packet, but the packet is
            // NOT finalized yet. Clearing finPending_ here would
            // make the pure-FIN retry path unreachable, and the FIN
            // would be lost if FinalizePpe() fails to flush.
            // ClearFinPending() is called below when nwrite > 0
            // (packet actually sent).
            ppeMaybePending = true;
            continue;
        }
        if (nwrite < 0) {
            // Error mid-encode. IMPORTANT: ngtcp2 sets PPE_PENDING *before*
            // returning errors like NGTCP2_ERR_STREAM_DATA_BLOCKED / SHUT_WR,
            // so we must ALWAYS flush with no-stream calls regardless of our
            // local tracking. Also mark the FIN as done so a blocked/errored
            // stream is never re-picked just for its FIN.
            if ((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) && sptr) {
                sptr->ClearFinPending();
            }
            FinalizePpe();
            break;   // error - stop driving
        }
        ppeMaybePending = false;
        if (nwrite == 0) break;  // congestion/flow-control blocked

        if (wdatalen > 0 && sptr) {
            sptr->AdvanceWrite(static_cast<size_t>(wdatalen));
        }
        // FIN is only set on the pure-FIN path (isPureFin), never on data
        // chunks. ClearFinPending is handled there and in the error path.

        bool sentOk = SendPacket(buf, static_cast<size_t>(nwrite));
        if (!sentOk) break;
        if (isPureFin && sptr) {
            // FIN packet actually handed to the socket: stop re-picking
            // this stream for its FIN on every Drive call.
            sptr->ClearFinPending();
        }
    }

    // Report ACK/loss deltas to the application congestion controller (only
    // when one is registered) and refresh the cached snapshot. Skipped
    // entirely otherwise: ngtcp2_conn_get_conn_info copies a large struct.
    ngtcp2_conn_info cinfo;
    if (congestion_ || Hy2DiagEnabled()) {
        ngtcp2_conn_get_conn_info(conn_, &cinfo);
        if (congestion_) {
            ReportAckedPackets(&cinfo);
            prevStat_ = cinfo;
            rttStats_.Update(Duration::FromNanos(cinfo.smoothed_rtt));
        }
        cinfo2_ = cinfo;
        if (Hy2DiagEnabled()) {
            diag_.lastCwnd.store(cinfo.cwnd, std::memory_order_relaxed);
            diag_.lastInflight.store(cinfo.bytes_in_flight, std::memory_order_relaxed);
            diag_.lastBytesSent.store(cinfo.bytes_sent, std::memory_order_relaxed);
            diag_.lastSmoothedRttNs.store(static_cast<int64_t>(cinfo.smoothed_rtt), std::memory_order_relaxed);
        }
    }

    if (Hy2DiagEnabled()) {
        auto tNow = std::chrono::steady_clock::now();
        const auto* s = socket_ ? socket_.get() : sendSocket_;
        sockStats_ = s ? s->GetStats() : UdpSocket::Stats();
        auto bufs = s ? s->GetActualBufferSizes() : UdpSocket::BufferSizes();
        std::fprintf(stderr, "[DRIVE-BREAKDOWN] snd=%d rcv=%d rxpkts=%lu onudprecv=%lu sendok=%lu sendfail=%lu\n",
            bufs.sndbuf, bufs.rcvbuf, (unsigned long)sockStats_.rxPackets,
            (unsigned long)diag_.readPktCalls.load(),
            (unsigned long)diag_.sendPacketSuccess.load(),
            (unsigned long)diag_.sendPacketFail.load());
        std::fprintf(stderr, "[DRIVE-BREAKDOWN] lock_ms=%lld loop_ms=%lld wv_ms=%lld report_ms=%lld drain_ms=%lld total_ms=%lld readpkt_ms=%lld send_ms=%lld cwnd=%lu inflight=%lu rtt_us=%lu lost=%lu tx=%lu rx=%lu qd=%lu de=%lu qn=%zu\n",
            (long long)std::chrono::duration_cast<std::chrono::milliseconds>(dLocked - dOpStart).count(),
            (long long)std::chrono::duration_cast<std::chrono::milliseconds>(dLoopEnd - dLoopStart).count(),
            (long long)(dWvNs / 1000000),
            (long long)std::chrono::duration_cast<std::chrono::milliseconds>(tNow - dLoopEnd).count(),
            (long long)0,
            (long long)std::chrono::duration_cast<std::chrono::milliseconds>(tNow - dOpStart).count(),
            (long long)(readPktNsAcc_ / 1000000),
            (long long)(sendNsBreakdown_ / 1000000),
            (unsigned long long)cinfo.cwnd, (unsigned long)cinfo.bytes_in_flight,
            (unsigned long)(cinfo.smoothed_rtt / 1000),
            (unsigned long)cinfo.pkt_lost,
            (unsigned long)cinfo.pkt_sent, (unsigned long)cinfo.pkt_recv,
            (unsigned long)sockStats_.txQueueDrop, (unsigned long)sockStats_.txDrainError,
            sockStats_.txQueueCount);
    }
    readPktNsAcc_ = 0;
    sendNsBreakdown_ = 0;

    // Drain any queued packets from WOULDBLOCK earlier
    if (socket_) socket_->DrainTxQueue();
    if (sendSocket_) sendSocket_->DrainTxQueue();
}

// Processes one datagram. Caller MUST hold opMu_ (BeginOpBlocking()).
// Returns false once the connection reached a terminal state.
bool Ngtcp2Connection::ReadPacketLocked(const uint8_t* data, size_t len) {
    if (closed_ || !conn_) return false;

    if (Hy2DiagEnabled()) {
        g_rxPackets.fetch_add(1, std::memory_order_relaxed);
        g_rxBytes.fetch_add(static_cast<int>(len), std::memory_order_relaxed);
        diag_.readPktCalls.fetch_add(1, std::memory_order_relaxed);
        if (QuicDebugEnabled() && len > 0) {
            uint8_t firstByte = data[0];
            bool isLong = (firstByte >> 7) & 1;
            const char* pktType = isLong ? QuicLongPacketTypeName(firstByte)
                                         : QuicPacketTypeName(firstByte);
            std::fprintf(stderr, "[DIAG-RX] t=%.1fms type=%s size=%zu total_rx=%d/%d\n",
                         ElapsedMs(), pktType, len, g_rxPackets.load(), g_rxBytes.load());
        }
    }

    ngtcp2_path* path = GetPath();
    ngtcp2_pkt_info pi{};

    TTRACE(1, (int64_t)len);
    std::chrono::steady_clock::time_point rpStart;
    if (Hy2DiagEnabled()) rpStart = std::chrono::steady_clock::now();
    int rv = ngtcp2_conn_read_pkt(conn_, path, &pi, data, len, NowTimestamp());
    if (Hy2DiagEnabled()) {
        readPktNsAcc_ += std::chrono::duration_cast<std::chrono::nanoseconds>(
                             std::chrono::steady_clock::now() - rpStart).count();
    }
    TTRACE(2, rv);
    if (QuicDebugEnabled()) {
        bool hs = conn_ ? ngtcp2_conn_get_handshake_completed2(conn_) : false;
        std::fprintf(stderr, "[DIAG] t=%.1fms read_pkt rv=%d handshake=%d\n",
                     ElapsedMs(), rv, (int)hs);
        if (rv != 0) {
            std::fprintf(stderr, "[DIAG] t=%.1fms read_pkt ERROR rv=%d\n", ElapsedMs(), rv);
        }
    }
    if (rv != 0) {
        // Both the idle timeout and the draining state entered after a
        // peer CONNECTION_CLOSE are terminal: this connection will never
        // serve another byte. Mark it closed so the listener can evict it
        // and a reconnect reusing the same UDP 4-tuple gets a fresh
        // connection instead of being routed into a dead one.
        if (rv == NGTCP2_ERR_IDLE_CLOSE || rv == NGTCP2_ERR_DRAINING) {
            // Terminal (peer CONNECTION_CLOSE, or the idle timeout fired).
            // Setting closed_ alone is NOT enough: every waiter parks on a
            // predicate over closed_ and only re-checks it when notified, so
            // without this wake the accept / uni-accept / datagram loops and
            // the stream readers stay blocked for the rest of the process
            // lifetime. HySession::Serve() joins those loops, so the session
            // worker never returned and its detached children were never torn
            // down: measured ~9 leaked threads and ~9MB per closed connection,
            // never reclaimed even after minutes of idle. Same reasoning as
            // the CloseWithError comment above; WakeAllWaiters is idempotent.
            closed_ = true;
            WakeAllWaiters();
            return false;
        }
        return true;
    }

    // Short-circuit on the cached flag first: once the handshake has been
    // observed complete this whole block is a no-op, and the old form ran
    // exchange(true) - a locked read-modify-write - on every received packet
    // for the entire life of the connection.
    if (!handshakeComplete_.load(std::memory_order_relaxed) &&
        ngtcp2_conn_get_handshake_completed2(conn_)) {
        if (!handshakeComplete_.exchange(true)) {
            g_handshakeCompleted = true;
            if (QuicDebugEnabled()) {
                std::fprintf(stderr, "[DIAG] t=%.1fms === HANDSHAKE COMPLETE === tx=%d/%d rx=%d/%d\n",
                             ElapsedMs(), g_txPackets.load(), g_txBytes.load(), g_rxPackets.load(), g_rxBytes.load());
            }
            DBG("HANDSHAKE COMPLETE");
            handshakeCv_.notify_all();
            if (listener_) {
                // First time completion on the server - hand to Accept().
                listener_->NotifyHandshakeComplete(shared_from_this());
            }
        }
    }
    return true;
}

void Ngtcp2Connection::OnUdpRecv(const uint8_t* data, size_t len,
                                   const struct sockaddr* /*addr*/, socklen_t /*addrlen*/) {
    if (closed_) return;
    BeginOpBlocking();
    {
        struct OpGuard {
            Ngtcp2Connection* c;
            ~OpGuard() { c->EndOp(); }
        } guard{this};
        ReadPacketLocked(data, len);
    }
    FlushReadNotifyBatch();
    // Flush everything (acks + any pending stream data). We released the op
    // lock above; the IO loop sees the pending flag and runs Drive(), which
    // bursts until cwnd is exhausted.
    MarkTxPending();
}

// Server worker variant: consumes a whole batch with ONE lock acquisition
// instead of one lock pair per datagram.
void Ngtcp2Connection::OnUdpRecvBatch(
    const std::deque<std::vector<uint8_t>>& batch) {
    if (closed_ || batch.empty()) return;
    BeginOpBlocking();
    {
        struct OpGuard {
            Ngtcp2Connection* c;
            ~OpGuard() { c->EndOp(); }
        } guard{this};
        for (const std::vector<uint8_t>& pkt : batch) {
            if (!ReadPacketLocked(pkt.data(), pkt.size())) break;
        }
    }
    FlushReadNotifyBatch();
    MarkTxPending();
}

// Wake the reader of every stream that got data in the last read batch.
// Runs on the IO thread; the pointers stay valid until the next Drive()
// (closed streams are only destroyed there, via zombieStreams_).
void Ngtcp2Connection::FlushReadNotifyBatch() {
    for (Ngtcp2Stream* s : readDirtyStreams_) {
        s->FlushReadNotify();
    }
    readDirtyStreams_.clear();
}

void Ngtcp2Connection::WakeAllWaiters() {
    // Unblock the IO loop's poll (a no-op once it has exited: the wake pipe's
    // send is non-blocking).
    WakeUp();
    // Release everything that parks on closed_ (datagram consumer, accept
    // waiters, stream readers/writers). The empty critical sections only
    // synchronize with the predicate check before a waiter parks - a bare
    // notify_all could race with one that has not entered wait() yet.
    {
        std::lock_guard<std::mutex> lk(datagramMu_);
    }
    datagramCv_.notify_all();
    {
        std::lock_guard<std::mutex> lk(acceptMu_);
    }
    acceptCv_.notify_all();
    {
        std::lock_guard<std::mutex> lk(uniAcceptMu_);
    }
    uniAcceptCv_.notify_all();
    NotifyStreamsClosed();
}

void Ngtcp2Connection::NotifyStreamsClosed() {
    // Snapshot under mu_ (the IO thread mutates streams_ from ngtcp2
    // callbacks), then notify outside every connection lock: the streams take
    // their own mutexes and wake their waiters.
    std::vector<std::shared_ptr<Ngtcp2Stream>> streams;
    {
        std::lock_guard<std::mutex> lk(mu_);
        // Zombies are streams ngtcp2 already closed: they stay in the map only
        // until the next Drive(), so both lists are needed to reach every
        // stream the application may still hold. (Everything parked in
        // pendingAccepts_ is also in streams_; nothing to do for those lists.)
        streams.reserve(streams_.size() + zombieStreams_.size());
        for (auto& kv : streams_) streams.push_back(kv.second);
        for (auto& s : zombieStreams_) streams.push_back(s);
    }
    for (auto& s : streams) {
        s->OnStreamClose(0);
    }
}

// ---------------------------------------------------------------------------
// Server-side worker loop
//
// The listener's single RecvLoop used to call OnUdpRecv()/Drive() for every
// server connection, so all QUIC crypto and state-machine work for ALL
// clients ran on one thread (~250-300 Mbps aggregate). Now RecvLoop is a
// pure dispatcher: it copies each datagram into the owning connection's
// queue and wakes that connection's worker below, so throughput scales with
// cores and connections.
// ---------------------------------------------------------------------------

void Ngtcp2Connection::EnqueueRx(const uint8_t* data, size_t len) {
    bool wake = false;
    {
        hy2::diag::LockTimer _hy2lt_1923("ngtcp2_connection:1923 rxMu_");
          std::lock_guard<std::mutex> lk(rxMu_);
          _hy2lt_1923.done();
        if (rxQueue_.size() >= kMaxRxQueue) {
            // Bound memory. QUIC recovers from drops via retransmission.
            return;
        }
        std::vector<uint8_t> buf;
        if (!rxPool_.empty()) {
            // Reuse a previously processed buffer: no allocation in steady state.
            buf = std::move(rxPool_.back());
            rxPool_.pop_back();
        }
        buf.resize(len);
        if (len > 0) {
            std::memcpy(buf.data(), data, len);
        }
        rxQueue_.push_back(std::move(buf));
        // Edge-triggered: the worker clears rxNotifyArmed_ (under rxMu_)
        // whenever it drains the queue, so one wakeup covers a whole burst
        // instead of one per datagram.
        if (!rxNotifyArmed_) {
            rxNotifyArmed_ = true;
            wake = true;
        }
    }
    if (wake) rxCv_.notify_one();
}

void Ngtcp2Connection::StartServerLoop() {
    if (serverLoopRunning_.exchange(true)) return;
    serverLoopStop_.store(false);
    auto self = shared_from_this();
    serverLoopThread_ = std::thread([self] { self->ServerLoop(); });
}

void Ngtcp2Connection::StopServerLoop() {
    serverLoopStop_.store(true);
    rxCv_.notify_all();
    if (serverLoopThread_.joinable()) {
        if (serverLoopThread_.get_id() == std::this_thread::get_id()) {
            // The loop is tearing the connection down from its own thread;
            // detach so ~thread() does not std::terminate.
            serverLoopThread_.detach();
        } else {
            serverLoopThread_.join();
        }
    }
}

void Ngtcp2Connection::Abort() {
    closed_.store(true);
    WakeAllWaiters();
}

void Ngtcp2Connection::DetachFromListener() {
    // Best effort by contract: the caller (Ngtcp2Listener::Close) has already
    // stopped this connection's worker loop, so only an application thread
    // inside Stream::Write() can still be reading these.
    wakeWrite_ = nullptr;
    sendSocket_ = nullptr;
    listener_ = nullptr;
}

void Ngtcp2Connection::ServerLoop() {
#ifdef _WIN32
    timeBeginPeriod(1);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
#endif
    std::deque<std::vector<uint8_t>> batch;
    const auto kMaxWait = std::chrono::milliseconds(100);
    static const bool diagEnabled = std::getenv("HY2_BW_DIAG") != nullptr;
    auto diagPrintTime = std::chrono::steady_clock::now();

    while (!serverLoopStop_.load() && !closed_.load()) {
        if (diagEnabled) {
            auto now = std::chrono::steady_clock::now();
            if (now - diagPrintTime >= std::chrono::seconds(1)) {
                diag_.Print("SERVERLOOP");
                diagPrintTime = now;
            }
        }
        if (Hy2DiagEnabled()) ConnHeartbeat("server");

        {
            hy2::diag::LockTimer _hy2lt_1998("ngtcp2_connection:1998 rxMu_");
              std::unique_lock<std::mutex> lk(rxMu_);
              _hy2lt_1998.done();
            if (rxQueue_.empty()) {
                auto deadline = std::chrono::steady_clock::now() + kMaxWait;
                auto expiry = GetExpiry();
                if (expiry < deadline) deadline = expiry;
                rxCv_.wait_until(lk, deadline, [&] {
                    return !rxQueue_.empty() || serverLoopStop_.load() ||
                           closed_.load();
                });
            }
            // Re-arm the edge trigger BEFORE swapping: an enqueue racing
            // with this drain must still notify (cleared and swapped under
            // the same lock, so no packet can slip in between).
            rxNotifyArmed_ = false;
            batch.swap(rxQueue_);
        }

        OnUdpRecvBatch(batch);
        // Recycle the datagram buffers for the next listener handoff.
        if (!batch.empty()) {
            hy2::diag::LockTimer _hy2lt_2018("ngtcp2_connection:2018 rxMu_");
              std::lock_guard<std::mutex> lk(rxMu_);
              _hy2lt_2018.done();
            for (auto& pkt : batch) {
                if (rxPool_.size() >= kMaxRxPool) break;
                rxPool_.push_back(std::move(pkt));
            }
        }
        batch.clear();

        if (serverLoopStop_.load() || closed_.load()) break;

        if (TimerOverdue()) {
            OnTimeout();
        }
        // Always drive: a received ACK frees cwnd and may owe an ACK, and the
        // old ConsumeTxPending() gate dropped exactly those drives (incoming
        // packets never set the app-write flag), so the peer's ACKs were only
        // answered on the next timer/PTO - throughput collapsed to one packet
        // per ACK-timeout on both sides.
        Drive();
        if (sendSocket_) {
            sendSocket_->DrainTxQueue();
        }
    }

    serverLoopRunning_.store(false);
    rxCv_.notify_all();

    // The server-side counterpart of the WakeAllWaiters() at the end of
    // InternalLoop(). This loop exits for every reason a connection can die -
    // the peer's CONNECTION_CLOSE, the idle timeout, a failed handle_expiry,
    // serverLoopStop_ - and once it has stopped nothing else will release the
    // threads parked on this connection. Without this the server-side accept /
    // uni-accept / datagram waiters and the stream readers stayed parked for
    // the rest of the process lifetime; because HySession::Serve() joins the
    // accept and datagram loops, the whole session worker and its detached
    // children were never torn down. Measured on the local server: ~9 threads
    // and ~9MB leaked per closed connection, never reclaimed even after
    // minutes of idle. The client path always had this; the server path did
    // not.
    WakeAllWaiters();
}

void Ngtcp2Connection::OnTimeout() {
    if (!conn_ || closed_) return;
    if (QuicDebugEnabled()) {
        auto exp = GetExpiry();
        auto now = std::chrono::steady_clock::now();
        std::fprintf(stderr, "[dbg] OnTimeout fired, overdue=%lldms\n",
                     (long long)std::chrono::duration_cast<std::chrono::milliseconds>(now - exp).count());
    }
    // Serialize with other ngtcp2 entry points (may contend briefly with an
    // app-thread SendDatagram).
    BeginOpBlocking();
    struct OpGuard {
        Ngtcp2Connection* c;
        ~OpGuard() { c->EndOp(); }
    } guard{this};

    int rv = ngtcp2_conn_handle_expiry(conn_, NowTimestamp());
    TTRACE(8, rv);
    if (rv != 0) {
        if (QuicDebugEnabled()) {
            std::fprintf(stderr, "[DIAG] t=%.1fms OnTimeout: handle_expiry FAILED rv=%d, setting closed_=true\n",
                         ElapsedMs(), rv);
        }
        closed_ = true;
        // Same as the read path above: closed_ is only a predicate for the
        // parked waiters, so they must be woken or they never observe it.
        WakeAllWaiters();
        return;
    }

    // handle_expiry may have scheduled PTO probes / retransmits: the IO
    // loop's Drive() flushes them (it bursts until cwnd is exhausted).
    MarkTxPending();
}

std::chrono::steady_clock::time_point Ngtcp2Connection::GetExpiry() const {
    if (!conn_) return std::chrono::steady_clock::time_point::max();
    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry2(conn_);
    // UINT64_MAX = no timer armed (ngtcp2 convention): wait forever.
    // Without this guard, `expiry - now` overflows int64 nanoseconds and
    // produces a deadline in the PAST, which makes an event-driven wait
    // spin OnTimeout at 100% CPU (the old polling loop masked this).
    if (expiry == UINT64_MAX) return std::chrono::steady_clock::time_point::max();
    ngtcp2_tstamp now = NowTimestamp();
    if (expiry <= now) return std::chrono::steady_clock::now();
    ngtcp2_tstamp delta = expiry - now;
    if (delta > static_cast<ngtcp2_tstamp>(std::numeric_limits<int64_t>::max())) {
        return std::chrono::steady_clock::time_point::max();
    }
    return std::chrono::steady_clock::now() + std::chrono::nanoseconds(delta);
}

int Ngtcp2Connection::GetSocketFd() const {
    if (socket_) return socket_->GetFd();
    return -1;
}

void Ngtcp2Connection::OnUdpRecvReady() {
    if (!socket_) return;
    uint8_t buf[4096];
    struct sockaddr_storage from{};
    socklen_t fromLen = sizeof(from);
    int n = socket_->RecvFrom(buf, sizeof(buf),
                               reinterpret_cast<struct sockaddr*>(&from), &fromLen);
    if (n > 0) {
        OnUdpRecv(buf, static_cast<size_t>(n),
                  reinterpret_cast<struct sockaddr*>(&from), fromLen);
        Drive();
    }
}

void Ngtcp2Connection::SetStreamAcceptCallback(
    std::function<void(std::shared_ptr<IQuicStream>)> cb) {
    streamAcceptCb_ = std::move(cb);
}

std::string Ngtcp2Connection::LocalHost() const {
    return socket_ ? socket_->LocalAddr() : "";
}

uint16_t Ngtcp2Connection::LocalPort() const {
    return socket_ ? socket_->LocalPort() : 0;
}

uint64_t Ngtcp2Connection::GetConnectionId() const {
    if (!conn_) return 0;
    const ngtcp2_cid* dcid = ngtcp2_conn_get_dcid2(conn_);
    if (!dcid) return 0;
    uint64_t id = 0;
    memcpy(&id, dcid->data, std::min(dcid->datalen, static_cast<size_t>(8)));
    return id;
}

Ngtcp2Connection::QuicStats Ngtcp2Connection::GetQuicStats() const {
    QuicStats qs;
    if (!conn_) return qs;

    ngtcp2_conn_info cinfo;
    ngtcp2_conn_get_conn_info(conn_, &cinfo);

    qs.bytesSent = cinfo.bytes_sent;
    qs.bytesReceived = cinfo.bytes_recv;
    qs.packetsSent = cinfo.pkt_sent;
    qs.packetsReceived = cinfo.pkt_recv;
    qs.packetsLost = cinfo.pkt_lost;
    qs.packetsRetransmitted = 0; // ngtcp2 1.25.0 removed retrans field
    qs.smoothedRttUs = static_cast<double>(cinfo.smoothed_rtt) / 1000.0; // ns �� us
    qs.cwnd = cinfo.cwnd;
    qs.bytesInFlight = cinfo.bytes_in_flight;
    qs.maxTxUdpPayloadSize = 0; // ngtcp2 1.25.0 removed this field from conn_info

    // Count streams
    hy2::diag::LockTimer _hy2lt_2152("ngtcp2_connection:2152 mu_");
      std::lock_guard<std::mutex> lk(mu_);
      _hy2lt_2152.done();
    qs.streamsOpen = streams_.size();
    uint64_t active = 0;
    for (auto& kv : streams_) {
        if (kv.second && kv.second->HasPendingWrite()) active++;
    }
    qs.streamsActive = active;

    return qs;
}

// IQuicConnection: the same counters, in the backend-neutral shape the rate
// controller uses (it must not know what a QuicStats is).
QuicStatsSnapshot Ngtcp2Connection::GetStatsSnapshot() const {
    const QuicStats qs = GetQuicStats();
    QuicStatsSnapshot out;
    out.bytesSent = qs.bytesSent;
    out.bytesReceived = qs.bytesReceived;
    out.packetsSent = qs.packetsSent;
    out.packetsReceived = qs.packetsReceived;
    out.packetsLost = qs.packetsLost;
    out.streamsActive = qs.streamsActive;
    out.streamsOpen = qs.streamsOpen;
    out.smoothedRttMs = qs.smoothedRttUs / 1000.0;  // us -> ms
    return out;
}

Ngtcp2Connection::SocketTxStats Ngtcp2Connection::GetSocketTxStats() const {
    SocketTxStats sts;
    // Server connections use sendSocket_ (listener's socket), not socket_
    const UdpSocket* sock = socket_ ? socket_.get() : sendSocket_;
    if (sock) {
        auto s = sock->GetStats();
        sts.sendSuccess = s.txSendSuccess;
        sts.queueCount = s.txQueueCount;
        sts.queueDrop = s.txQueueDrop;
        sts.drainSuccess = s.txDrainSuccess;
        sts.drainWouldBlock = s.txDrainWouldBlock;
    }
    return sts;
}

void Ngtcp2Connection::ConnHeartbeat(const char* role) {
    static std::chrono::steady_clock::time_point next{};
    const auto now = std::chrono::steady_clock::now();
    if (now < next) return;
    next = now + std::chrono::seconds(1);
    ngtcp2_conn_info ci{};
    uint64_t cwnd = 0, inflight = 0;
    if (conn_) {
        ngtcp2_conn_get_conn_info(conn_, &ci);
        cwnd = ci.cwnd;
        inflight = ci.bytes_in_flight;
    }
    std::fprintf(stderr,
                 "[hb] role=%s closed=%d loops=%llu rx=%llu tx=%llu drives=%llu rv0=%llu "
                 "cwnd=%llu inflight=%llu\n",
                 role, (int)closed_.load(),
                 (unsigned long long)diag_.loopCount.load(),
                 (unsigned long long)diag_.recvPackets.load(),
                 (unsigned long long)diag_.sendPacketSuccess.load(),
                 (unsigned long long)diag_.driveCalls.load(),
                 (unsigned long long)g_driveRv0.load(), (unsigned long long)cwnd,
                 (unsigned long long)inflight);
    std::fflush(stderr);
    std::vector<std::shared_ptr<Ngtcp2Stream>> snapshot;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& kv : streams_) snapshot.push_back(kv.second);
    }
    for (auto& s : snapshot) s->DiagPrint();
}

void Ngtcp2Connection::PrintStats() const {
    auto qs = GetQuicStats();
    auto socketStats = socket_ ? socket_->GetStats() : UdpSocket::Stats();
    auto bs = socket_ ? socket_->GetActualBufferSizes() : UdpSocket::BufferSizes();
    std::fprintf(stderr,
        "[conn %llu] QUIC: rtt=%.0fus cwnd=%lu inflight=%lu "
        "tx=%lu rx=%lu lost=%lu retrans=%lu streams=%lu/%lu\n"
        "[conn %llu] SOCK: sndbuf=%d rcvbuf=%d\n"
        "[conn %llu] TXQ: success=%lu queue=%lu drop=%lu peak=%zu drain_wb=%lu\n",
        (unsigned long long)GetConnectionId(),
        qs.smoothedRttUs,
        (unsigned long)qs.cwnd,
        (unsigned long)qs.bytesInFlight,
        (unsigned long)qs.packetsSent,
        (unsigned long)qs.packetsReceived,
        (unsigned long)qs.packetsLost,
        (unsigned long)qs.packetsRetransmitted,
        (unsigned long)qs.streamsActive,
        (unsigned long)qs.streamsOpen,
        (unsigned long long)GetConnectionId(),
        bs.sndbuf, bs.rcvbuf,
        (unsigned long long)GetConnectionId(),
        (unsigned long)socketStats.txSendSuccess,
        (unsigned long)socketStats.txQueueCount,
        (unsigned long)socketStats.txQueueDrop,
        socketStats.txQueuePeak,
        (unsigned long)socketStats.txDrainWouldBlock);
}

// ---------------------------------------------------------------------------
// ACK/loss reporting to congestion controller
// ---------------------------------------------------------------------------

void Ngtcp2Connection::ReportAckedPackets(const ngtcp2_conn_info* cinfo) {
    if (!congestion_) return;

    int64_t ackedDelta = static_cast<int64_t>(prevStat_.bytes_in_flight) -
                         static_cast<int64_t>(cinfo->bytes_in_flight);
    if (ackedDelta > 0) {
        congestion_->OnPacketAcked(
            0,
            static_cast<uint64_t>(ackedDelta),
            cinfo->bytes_in_flight,
            MonoTime::Now());
    }
}

void Ngtcp2Connection::ReportLostPackets() {
    if (!congestion_) return;
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

void Ngtcp2Connection::Diag::Print(const char* tag) const {
    uint64_t calls = dgramTxCalls.load();
    uint64_t succ = dgramTxSuccess.load();
    uint64_t acc0 = dgramTxAccepted0.load();
    uint64_t rv0 = dgramTxRv0.load();
    uint64_t rvNeg = dgramTxRvNeg.load();
    uint64_t lockWait = dgramTxLockWaitNs.load();
    uint64_t lockHold = dgramTxLockHoldNs.load();

    uint64_t loops = loopCount.load();
    uint64_t recv = recvPackets.load();
    uint64_t drives = driveCalls.load();
    uint64_t driveTime = driveNs.load();

    uint64_t readPkts = readPktCalls.load();

    uint64_t cwnd = lastCwnd.load();
    uint64_t inflight = lastInflight.load();
    uint64_t bytesSent = lastBytesSent.load();
    int64_t rttNs = lastSmoothedRttNs.load();

    std::fprintf(stderr,
        "\n[%s] === DIAGNOSTIC SNAPSHOT ===\n"
        "[%s] [DGRAM-TX] calls=%lu success=%lu accepted0=%lu rv0=%lu rvNeg=%lu\n"
        "[%s] [DGRAM-TX] lock_wait_us=%lu lock_hold_us=%lu\n"
        "[%s] [EVENTLOOP] loops=%lu recv=%lu drives=%lu drive_us=%lu\n"
        "[%s] [ACK] read_pkt=%lu\n"
        "[%s] [CONGESTION] cwnd=%lu inflight=%lu bytes_sent=%lu rtt_us=%lu\n"
        "[%s] ============================\n",
        tag, tag,
        (unsigned long)calls, (unsigned long)succ, (unsigned long)acc0,
        (unsigned long)rv0, (unsigned long)rvNeg, tag,
        (unsigned long)(lockWait / 1000), (unsigned long)(lockHold / 1000), tag,
        (unsigned long)loops, (unsigned long)recv, (unsigned long)drives,
        (unsigned long)(driveTime / 1000), tag,
        (unsigned long)readPkts, tag,
        (unsigned long)cwnd, (unsigned long)inflight, (unsigned long)bytesSent,
        (unsigned long)(rttNs / 1000), tag);
    std::fflush(stderr);
}

void Ngtcp2Connection::Diag::Reset() {
    dgramTxCalls = 0;
    dgramTxSuccess = 0;
    dgramTxAccepted0 = 0;
    dgramTxRv0 = 0;
    dgramTxRvNeg = 0;
    dgramTxLockWaitNs = 0;
    dgramTxLockHoldNs = 0;
    loopCount = 0;
    recvPackets = 0;
    ackPackets = 0;
    driveCalls = 0;
    driveNs = 0;
    readPktCalls = 0;
    ackProcessed = 0;
    drivingLockAcquires = 0;
    drivingLockContentions = 0;
    drivingLockWaitNs = 0;
    drivingLockHoldNs = 0;
}

// ---------------------------------------------------------------------------
// Destruction
// ---------------------------------------------------------------------------

Ngtcp2Connection::~Ngtcp2Connection() {
    StopServerLoop();
    StopInternalLoop();
    // The application can still hold streams of this connection (a flow whose
    // Client was dropped from the pool). Release their waiters before the
    // object goes away: the weak back-reference dies with us, so from here on
    // Read()/Write() would either park forever or try to notify a dead loop.
    // WakeAllWaiters() rather than NotifyStreamsClosed() so every path that ends
    // a connection's life releases the same set of waiters - the datagram and
    // accept waiters hold a shared_ptr, so they cannot be parked here, but the
    // invariant is worth keeping uniform.
    WakeAllWaiters();
    CloseClientWakePipe();
    if (conn_) {
        ngtcp2_conn_del(conn_);
        conn_ = nullptr;
    }
    if (ssl_) {
        SSL_set_app_data(ssl_, nullptr); // required before SSL_free (ossl docs)
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (osslCtx_) {
        ngtcp2_crypto_ossl_ctx_del(osslCtx_);
        osslCtx_ = nullptr;
    }
    if (sslCtx_ && ownsSslCtx_) {
        SSL_CTX_free(sslCtx_);
        sslCtx_ = nullptr;
    }
    if (socket_) {
        socket_->Close();
    }
}

} // namespace hy2::quic_backend
