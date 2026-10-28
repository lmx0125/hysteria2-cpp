// proxy_engine_perf_test.cpp - Regression tests for the alyssum_proxy data
// plane hot paths that were measured and reworked:
//
//   H1  Upload: one stream->Write() per burst, not one per MSS-sized item.
//       Every Write wakes the connection's IO loop through the wake pipe:
//       one send() syscall + one poll return + one Drive() per 1400 bytes,
//       which is the largest fixed cost on the upload path.
//   H3  Download: the sequence range is reserved under conn->mtx but the packet
//       (payload copy + both checksums) is built OUTSIDE the lock, so a
//       download segment's checksum no longer queues the ACK path behind it.
//   H4  Checksum: multi-lane one's-complement sum - bit-identical to a serial
//       reference sum at every length, odd tails included.
//   H5  IP ID is per-thread instead of one shared atomic (one cache line, one
//       locked RMW per packet), and the stats types keep their byte counters
//       on separate cache lines.
//   L1  Connection ids: 64-bit avalanche instead of an XOR fold, so flows that
//       used to collide stay in separate sessions.
//   H2  The client's QUIC receive drain is bounded per loop turn - covered by
//       the real-QUIC test at the bottom of this file.
//
// Everything except the last test runs against the real engine sources
// compiled into this runner (tests/CMakeLists.txt) with an in-memory stream:
// no network, no TUN, no administrator rights.

#include "hytest.hpp"

#include "proxy_engine.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#error "proxy engine tests are Windows-only (packet_parser uses winsock types)"
#endif

using namespace proxy;

namespace {

// ---------------------------------------------------------------------------
// Reference checksum: the classic serial one's-complement sum.
//
// Deliberately independent of the engine's AddWordsFold (which now uses four
// accumulation lanes and folds once at the end - only correct because the sum
// is associative under end-around carry). Every test below compares the
// engine's packets against THIS function.
// ---------------------------------------------------------------------------

uint32_t AddWordsSerial(uint32_t sum, const uint8_t* data, size_t len) {
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (len & 1) {
        sum += static_cast<uint32_t>(data[len - 1]) << 8;
    }
    return sum;
}

uint16_t FoldSerial(uint32_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

uint16_t IpChecksumRef(const uint8_t* data, size_t len) {
    return FoldSerial(AddWordsSerial(0, data, len));
}

uint16_t L4ChecksumRef(const uint8_t* data, size_t len, uint32_t srcIp, uint32_t dstIp,
                       uint8_t proto) {
    uint32_t sum = 0;
    sum += (srcIp >> 16) & 0xFFFF;
    sum += srcIp & 0xFFFF;
    sum += (dstIp >> 16) & 0xFFFF;
    sum += dstIp & 0xFFFF;
    sum += proto;
    sum += static_cast<uint16_t>(len);
    return FoldSerial(AddWordsSerial(sum, data, len));
}

// ---------------------------------------------------------------------------
// Host -> engine packet builders (host-order IPs, like packet_parser)
// ---------------------------------------------------------------------------

std::vector<BYTE> MakeIpTcp(uint32_t srcIp, uint32_t dstIp, uint16_t srcPort,
                            uint16_t dstPort, uint32_t seq, uint32_t ack, uint8_t flags,
                            const std::vector<uint8_t>& payload,
                            const std::vector<uint8_t>& options = {}) {
    const size_t optionsPadded = (options.size() + 3) & ~static_cast<size_t>(3);
    const size_t tcpLen = 20 + optionsPadded + payload.size();
    const size_t total = 20 + tcpLen;
    std::vector<BYTE> pkt(total, 0);
    pkt[0] = 0x45;
    pkt[2] = static_cast<BYTE>(total >> 8);
    pkt[3] = static_cast<BYTE>(total & 0xFF);
    pkt[8] = 64;
    pkt[9] = 6;
    const uint32_t srcN = htonl(srcIp), dstN = htonl(dstIp);
    std::memcpy(&pkt[12], &srcN, 4);
    std::memcpy(&pkt[16], &dstN, 4);
    const uint16_t ipc = IpChecksumRef(pkt.data(), 20);
    pkt[10] = static_cast<BYTE>(ipc >> 8);
    pkt[11] = static_cast<BYTE>(ipc & 0xFF);

    BYTE* tcp = pkt.data() + 20;
    tcp[0] = static_cast<BYTE>(srcPort >> 8);
    tcp[1] = static_cast<BYTE>(srcPort & 0xFF);
    tcp[2] = static_cast<BYTE>(dstPort >> 8);
    tcp[3] = static_cast<BYTE>(dstPort & 0xFF);
    const uint32_t seqN = htonl(seq), ackN = htonl(ack);
    std::memcpy(tcp + 4, &seqN, 4);
    std::memcpy(tcp + 8, &ackN, 4);
    tcp[12] = static_cast<BYTE>(((20 + optionsPadded) / 4) << 4);
    tcp[13] = flags;
    tcp[14] = 0xFF;
    tcp[15] = 0xFF;  // window field 65535 (never scaled on a SYN)
    if (!options.empty()) {
        std::memcpy(tcp + 20, options.data(), options.size());
        for (size_t i = options.size(); i < optionsPadded; i++) tcp[20 + i] = 0;
    }
    if (!payload.empty()) std::memcpy(tcp + 20 + optionsPadded, payload.data(), payload.size());
    const uint16_t csum = L4ChecksumRef(tcp, tcpLen, srcIp, dstIp, 6);
    tcp[16] = static_cast<BYTE>(csum >> 8);
    tcp[17] = static_cast<BYTE>(csum & 0xFF);
    return pkt;
}

// A SYN that offers window scaling, so the engine learns the peer's shift and
// later ACKs can advertise a real (multi-MB) window instead of 64 KB. Without
// it every relay parks on the window after 65535 in-flight bytes.
std::vector<uint8_t> MakeSynWithWindowScale(uint32_t srcIp, uint32_t dstIp,
                                            uint16_t srcPort, uint16_t dstPort,
                                            uint32_t seq, uint8_t scale) {
    std::vector<uint8_t> options;
    options.push_back(2); options.push_back(4); options.push_back(0x05); options.push_back(0xB4);
    options.push_back(3); options.push_back(3); options.push_back(scale);
    while (options.size() % 4 != 0) options.push_back(1);  // NOP padding
    return MakeIpTcp(srcIp, dstIp, srcPort, dstPort, seq, 0, 0x02, {}, options);
}

struct ParsedTcp {
    bool valid = false;
    uint16_t srcPort = 0, dstPort = 0;
    uint32_t seq = 0, ack = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> payload;
    bool ipChecksumOk = false;
    bool tcpChecksumOk = false;
};

ParsedTcp ParseTcpRef(const std::vector<BYTE>& pkt) {
    ParsedTcp r;
    if (pkt.size() < 40 || pkt[0] != 0x45) return r;
    const uint32_t srcIp = (static_cast<uint32_t>(pkt[12]) << 24) |
                           (static_cast<uint32_t>(pkt[13]) << 16) |
                           (static_cast<uint32_t>(pkt[14]) << 8) | pkt[15];
    const uint32_t dstIp = (static_cast<uint32_t>(pkt[16]) << 24) |
                           (static_cast<uint32_t>(pkt[17]) << 16) |
                           (static_cast<uint32_t>(pkt[18]) << 8) | pkt[19];
    std::vector<uint8_t> iph(pkt.begin(), pkt.begin() + 20);
    const uint16_t storedIp = static_cast<uint16_t>((iph[10] << 8) | iph[11]);
    iph[10] = iph[11] = 0;
    r.ipChecksumOk = (IpChecksumRef(iph.data(), 20) == storedIp);

    const BYTE* tcp = pkt.data() + 20;
    const size_t tcpLen = pkt.size() - 20;
    r.srcPort = static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
    r.dstPort = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
    r.seq = (static_cast<uint32_t>(tcp[4]) << 24) | (static_cast<uint32_t>(tcp[5]) << 16) |
            (static_cast<uint32_t>(tcp[6]) << 8) | tcp[7];
    r.ack = (static_cast<uint32_t>(tcp[8]) << 24) | (static_cast<uint32_t>(tcp[9]) << 16) |
            (static_cast<uint32_t>(tcp[10]) << 8) | tcp[11];
    r.flags = tcp[13];
    const size_t hdrLen = static_cast<size_t>((tcp[12] >> 4) & 0x0F) * 4;
    if (tcpLen >= hdrLen) {
        r.payload.assign(pkt.begin() + 20 + static_cast<long>(hdrLen), pkt.end());
    }
    const uint16_t storedTcp = static_cast<uint16_t>((tcp[16] << 8) | tcp[17]);
    std::vector<uint8_t> tcpCopy(tcp, tcp + tcpLen);
    tcpCopy[16] = tcpCopy[17] = 0;
    r.tcpChecksumOk = (L4ChecksumRef(tcpCopy.data(), tcpLen, srcIp, dstIp, 6) == storedTcp);
    r.valid = true;
    return r;
}

bool WaitForCond(const std::function<bool()>& cond, int timeoutMs = 5000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return cond();
}

// ---------------------------------------------------------------------------
// Engine-side stream.
//
// Two directions that must never share a queue: the engine writes upload bytes
// into fromEngine_ (what the test drains) and reads download bytes out of
// toEngine_ (what the test feeds). Sharing one queue would hand the engine its
// own output.
//
// Write() also counts how often the engine called it - exactly what the H1
// regression measures.
// ---------------------------------------------------------------------------

class PerfStream : public hy2::IByteReaderWriter {
public:
    size_t Read(uint8_t* p, size_t n) override {
        std::unique_lock<std::mutex> lk(mu_);
        haveData_.wait(lk, [&] { return closed_ || !toEngine_.empty(); });
        if (toEngine_.empty()) return 0;  // EOF
        std::vector<uint8_t>& front = toEngine_.front();
        const size_t got = std::min(n, front.size());
        std::memcpy(p, front.data(), got);
        if (got == front.size()) {
            toEngine_.pop_front();
        } else {
            front.erase(front.begin(), front.begin() + static_cast<ptrdiff_t>(got));
        }
        return got;
    }

    void Write(const uint8_t* p, size_t n) override {
        std::unique_lock<std::mutex> lk(mu_);
        // Park until the test releases the stream: it must be able to queue a
        // whole burst before the writer gets to hand it to the stream (H1).
        haveData_.wait(lk, [&] { return !holdWrite_.load(std::memory_order_relaxed) ||
                                        closed_; });
        writes_.fetch_add(1, std::memory_order_relaxed);
        written_.fetch_add(n, std::memory_order_relaxed);
        fromEngine_.emplace_back(p, p + n);
        haveData_.notify_all();
    }

    void Close() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            closed_ = true;
        }
        haveData_.notify_all();
    }

    // --- test side ---
    void Feed(const std::vector<uint8_t>& bytes) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            toEngine_.push_back(bytes);
        }
        haveData_.notify_all();
    }

    // While held, Write() parks (so a burst accumulates before the writer runs).
    void SetHoldWrite(bool hold) {
        holdWrite_.store(hold, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lk(mu_);
            haveData_.notify_all();
        }
    }

    // Everything the engine wrote since the last call, in order. The engine
    // only ever appends, so the queue can be emptied in place: a copy would add
    // one allocation per drained chunk to a path that is being measured.
    std::vector<std::vector<uint8_t>> TakeWrittenChunks() {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::vector<uint8_t>> out;
        out.reserve(fromEngine_.size());
        for (auto& c : fromEngine_) out.push_back(std::move(c));
        fromEngine_.clear();
        return out;
    }

    size_t WriteCalls() const { return writes_.load(std::memory_order_relaxed); }
    size_t BytesWritten() const { return written_.load(std::memory_order_relaxed); }

private:
    std::mutex mu_;
    std::condition_variable haveData_;
    bool closed_ = false;
    std::atomic<bool> holdWrite_{false};
    std::deque<std::vector<uint8_t>> toEngine_;
    std::deque<std::vector<uint8_t>> fromEngine_;
    std::atomic<size_t> writes_{0};
    std::atomic<size_t> written_{0};
};

// Hands out one stream per dial, so a test can tell two connections apart.
struct PerfMockClient : public hy2::client::Client {
    std::mutex mu;
    std::vector<std::shared_ptr<PerfStream>> streams;

    std::shared_ptr<hy2::IByteReaderWriter> TCP(const std::string&) override {
        auto s = std::make_shared<PerfStream>();
        std::lock_guard<std::mutex> lk(mu);
        streams.push_back(s);
        return s;
    }
    std::shared_ptr<hy2::client::HyUDPConn> UDP() override { return nullptr; }
    void Close() override {}
};

// Everything the engine sent back to the host, in order.
struct Output {
    std::mutex mu;
    std::vector<std::vector<BYTE>> pkts;
    void Add(const BYTE* d, DWORD n) {
        std::lock_guard<std::mutex> lk(mu);
        pkts.emplace_back(d, d + n);
    }
    size_t Size() {
        std::lock_guard<std::mutex> lk(mu);
        return pkts.size();
    }
    std::vector<BYTE> At(size_t i) {
        std::lock_guard<std::mutex> lk(mu);
        return pkts[i];
    }
    std::vector<std::vector<BYTE>> From(size_t from) {
        std::lock_guard<std::mutex> lk(mu);
        if (from >= pkts.size()) return {};
        return std::vector<std::vector<BYTE>>(pkts.begin() + static_cast<long>(from),
                                              pkts.end());
    }
    std::vector<std::vector<BYTE>> Snapshot() {
        std::lock_guard<std::mutex> lk(mu);
        return pkts;
    }
    void Clear() {
        std::lock_guard<std::mutex> lk(mu);
        pkts.clear();
    }
};

constexpr uint32_t kHostIp = 0x0A000001;    // 10.0.0.1 (the local host)
constexpr uint32_t kTargetIp = 0x08080808;  // 8.8.8.8
constexpr uint16_t kTargetPort = 80;
constexpr size_t kMaxTcpPayload = 1400;
// The window shift every fixture's SYN offers; the engine learns it and scales
// the window field of every later ACK by it.
constexpr uint8_t kOurWindowScaleShift = 6;

// One completed TCP connection through the real engine. The engine (and its
// client) may be shared by several fixtures: the session table is what
// PerfEngine_ConnIdCollidingTuplesStaySeparate exercises.
struct TcpFixture {
    std::shared_ptr<ProxyEngine> engine;
    std::shared_ptr<PerfMockClient> client;
    std::shared_ptr<PerfStream> stream;
    std::shared_ptr<Output> out;
    uint32_t srcIp = 0, dstIp = 0;
    uint16_t srcPort = 0, dstPort = 0;
    uint32_t clientIsn = 0;
    uint32_t serverIsn = 0;  // first sequence number the engine will send
    bool ownsEngine = false;

    TcpFixture(uint16_t hostPort, uint32_t isn = 12345) {
        ownsEngine = true;
        Start(std::make_shared<ProxyEngine>(), std::make_shared<PerfMockClient>(), hostPort,
              kHostIp, kTargetIp, kTargetPort, isn);
    }

    TcpFixture(std::shared_ptr<ProxyEngine> eng, std::shared_ptr<PerfMockClient> cli,
               uint16_t hostPort, uint32_t src, uint32_t dst, uint16_t dport, uint32_t isn) {
        Start(std::move(eng), std::move(cli), hostPort, src, dst, dport, isn);
    }

    void Start(std::shared_ptr<ProxyEngine> eng, std::shared_ptr<PerfMockClient> cli,
               uint16_t hostPort, uint32_t src, uint32_t dst, uint16_t dport, uint32_t isn) {
        engine = std::move(eng);
        client = std::move(cli);
        if (!engine->IsConnected()) engine->SetClient(client);
        srcIp = src;
        dstIp = dst;
        srcPort = hostPort;
        dstPort = dport;
        clientIsn = isn;
        out = std::make_shared<Output>();

        auto syn = MakeSynWithWindowScale(srcIp, dstIp, srcPort, dstPort, isn,
                                         kOurWindowScaleShift);
        auto info = packet_parser::ParsePacket(syn.data(), static_cast<DWORD>(syn.size()));
        HY_CHECK(info.valid);
        auto sendBack = SendBack();
        HY_CHECK(engine->HandleTcpPacket(info, syn.data(), static_cast<DWORD>(syn.size()),
                                         sendBack));
        HY_CHECK(WaitForCond([this] { return out->Size() >= 1; }));
        const auto synAck = ParseTcpRef(out->At(0));
        HY_CHECK(synAck.valid);
        HY_CHECK_EQ(synAck.flags, static_cast<uint8_t>(0x12));
        serverIsn = synAck.seq;
        out->Clear();

        {
            std::lock_guard<std::mutex> lk(client->mu);
            HY_CHECK(!client->streams.empty());
            stream = client->streams.back();
        }

        // Full receive window so the read loop never parks on the window gate.
        auto ack = MakeIpTcp(srcIp, dstIp, srcPort, dstPort, isn + 1, synAck.seq + 1,
                             0x10 /*ACK*/, {});
        auto ackInfo = packet_parser::ParsePacket(ack.data(), static_cast<DWORD>(ack.size()));
        HY_CHECK(engine->HandleTcpPacket(ackInfo, ack.data(), static_cast<DWORD>(ack.size()),
                                         sendBack));
        out->Clear();
    }

    std::function<bool(const BYTE*, DWORD)> SendBack() {
        return [this](const BYTE* d, DWORD n) {
            out->Add(d, n);
            return true;
        };
    }

    // Upload one segment from the host side. `ack` defaults to "everything the
    // engine has sent so far"; a test that tracks it explicitly (window tests)
    // can pass its own.
    bool SendFromHost(uint32_t seq, uint8_t flags, const std::vector<uint8_t>& payload,
                      uint32_t ack = 0) {
        if (ack == 0) ack = serverIsn + 1;
        auto pkt = MakeIpTcp(srcIp, dstIp, srcPort, dstPort, seq, ack, flags, payload);
        auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
        return engine->HandleTcpPacket(info, pkt.data(), static_cast<DWORD>(pkt.size()),
                                       SendBack());
    }

    ~TcpFixture() {
        if (stream) stream->Close();
        if (ownsEngine && engine) engine->Close();
    }
};

// Walks `out` from `processed`, validating every data segment: both checksums
// against the reference implementation and a strictly contiguous sequence
// chain starting at `expectedSeq` (advanced as it goes). Returns the number
// of data segments validated, or -1 on the first failure.
long long ValidateDownload(std::shared_ptr<Output>& out, size_t& processed,
                           uint32_t& expectedSeq, std::vector<uint8_t>* collect) {
    long long segments = 0;
    for (const auto& raw : out->From(processed)) {
        processed++;
        const auto p = ParseTcpRef(raw);
        if (!p.valid) return -1;
        if (!(p.flags & 0x08)) continue;  // PSH marks a data segment
        if (!p.ipChecksumOk || !p.tcpChecksumOk) return -1;
        if (p.seq != expectedSeq) return -1;
        if (collect) collect->insert(collect->end(), p.payload.begin(), p.payload.end());
        expectedSeq += static_cast<uint32_t>(p.payload.size());
        segments++;
    }
    return segments;
}

std::vector<uint8_t> PatternBytes(size_t n, uint32_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; i++) {
        v[i] = static_cast<uint8_t>((i * 131u + seed * 7919u) & 0xFF);
    }
    return v;
}

// ---------------------------------------------------------------------------
// H5 (structural): the byte counters written per packet must not share a cache
// line - the packet thread counts upload bytes on one of them and the relay
// thread counts download bytes on the other.
// ---------------------------------------------------------------------------
static_assert(alignof(ConnectionStats) >= 64,
              "ConnectionStats must start cache-line aligned");
static_assert(offsetof(ConnectionStats, bytesOut) -
                      offsetof(ConnectionStats, bytesIn) >= 64,
              "bytesIn and bytesOut are written from different threads");

// ---------------------------------------------------------------------------
// H1: one Write() per upload burst.
//
// The engine queues one MSS-sized item per packet. Before the fix the writer
// called stream->Write() once per item, and every Write() wakes the
// connection's IO loop through the wake pipe (send() + poll return + Drive()):
// at 415 Mbps that is ~37k syscalls and ~37k loop round trips a second, i.e.
// roughly 0.7 of a CPU's worth of pure overhead - and the reason upload used to
// run below download on the same link.
//
// The test waits until the engine has queued the whole burst (stats) and the
// stream has already been handed at least one Write(), so the two
// implementations differ categorically: one call per item = kSegments calls,
// one call per burst = a handful.
// ---------------------------------------------------------------------------
HY_TEST(PerfEngine_UploadBurstCoalescedIntoOneWrite) {
    constexpr int kSegments = 40;
    constexpr size_t kSegmentBytes = 1400;
    constexpr size_t kTotal = kSegments * kSegmentBytes;
    constexpr uint16_t kPort = 41001;

    TcpFixture fx(kPort);
    // Park the stream inside Write() so the writer cannot drain the queue one
    // item at a time: the whole burst is queued before it is released, which
    // is the situation the merge exists for.
    fx.stream->SetHoldWrite(true);

    uint32_t seq = fx.clientIsn + 1;
    for (int i = 0; i < kSegments; i++) {
        std::vector<uint8_t> payload(kSegmentBytes);
        std::memset(payload.data(), i & 0xFF, payload.size());
        HY_CHECK(fx.SendFromHost(seq, 0x18 /*PSH|ACK*/, payload));
        seq += static_cast<uint32_t>(payload.size());
    }
    // The burst is fully queued once the engine has accounted for every byte.
    HY_CHECK(WaitForCond([&] { return fx.engine->GetStats().totalBytesOut >= kTotal; }));
    // The writer is parked in (or about to enter) Write(): let it through and
    // it will find everything that is left in one swap.
    fx.stream->SetHoldWrite(false);

    std::vector<uint8_t> got;
    const bool done = WaitForCond(
        [&] {
            for (auto& chunk : fx.stream->TakeWrittenChunks()) {
                got.insert(got.end(), chunk.begin(), chunk.end());
            }
            return got.size() >= kTotal;
        },
        5000);

    if (!done) {
        std::printf("[perf-h1] only %zu of %zu upload bytes reached the stream "
                    "(%zu Write calls)\n",
                    got.size(), kTotal, fx.stream->WriteCalls());
    }
    HY_CHECK(done);
    HY_CHECK_EQ(got.size(), kTotal);
    // Order is preserved through the queue no matter how it is chunked.
    for (int i = 0; i < kSegments; i++) {
        const uint8_t tag = static_cast<uint8_t>(i & 0xFF);
        for (size_t b = 0; b < kSegmentBytes; b++) {
            HY_CHECK_EQ(got[static_cast<size_t>(i) * kSegmentBytes + b], tag);
        }
    }
    const size_t writes = fx.stream->WriteCalls();
    std::printf("[perf-h1] %d x %zu B upload segments -> %zu stream Write() calls "
                "(was %d)\n",
                kSegments, kSegmentBytes, writes, kSegments);
    // One Write per segment is the regression; a couple of calls is the fix.
    HY_CHECK(writes >= 1);
    HY_CHECK(writes < kSegments / 2);
}

// ---------------------------------------------------------------------------
// H4: the multi-lane checksum is bit-identical to the reference serial sum.
//
// AddWordsFold accumulates in four lanes and folds once at the end. That is
// only valid because the one's-complement sum is associative under end-around
// carry - which is what these checks prove, at lane boundaries (multiples of
// 8), odd tails, and the 1400-byte segmentation boundary that produces a
// one-byte final chunk.
// ---------------------------------------------------------------------------
HY_TEST(PerfEngine_ChecksumMatchesSerialReference) {
    static const size_t kLengths[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 23, 31, 32, 33, 63, 64, 65,
        127, 255, 256, 1000, 1399, 1400, 1401, 1402, 2799, 2800, 2801,
        4095, 4096, 4097, 8191, 8192, 8193, 16384, 20000, 32768, 40000,
    };
    constexpr uint32_t kSeed = 7;

    for (size_t len : kLengths) {
        TcpFixture fx(42000, 500000 + static_cast<uint32_t>(len));
        const std::vector<uint8_t> data = PatternBytes(len, kSeed);
        fx.stream->Feed(data);

        std::vector<uint8_t> got;
        uint32_t expectedSeq = fx.serverIsn + 1;
        size_t processed = 0;
        long long segments = 0;
        const bool ok = WaitForCond(
            [&] {
                const long long s = ValidateDownload(fx.out, processed, expectedSeq, &got);
                if (s > 0) segments += s;
                return got.size() >= data.size();
            },
            5000);
        if (!ok) {
            std::printf("[perf-h4] len=%zu: received %zu of %zu bytes\n", len, got.size(),
                        data.size());
        }
        HY_CHECK(ok);
        HY_CHECK(segments > 0);
        HY_CHECK_EQ(got.size(), data.size());
        HY_CHECK(got == data);
    }
}

// ---------------------------------------------------------------------------
// H3: building the download packet outside conn->mtx keeps the sequence chain
// intact and the checksums valid while the packet thread hammers the same
// connection's lock with ACKs.
//
// Before the fix the payload copy and both checksums ran inside conn->mtx, so
// every ACK (built on the packet thread) queued behind a download segment's
// checksum and vice versa. The reservation (seq + window field) is what has to
// stay atomic; everything else is now outside. A race here shows up as a
// non-contiguous sequence number, a bad checksum or a wrong payload.
// ---------------------------------------------------------------------------
HY_TEST(PerfEngine_DownloadSeqAndChecksumUnderConcurrentAck) {
    constexpr uint16_t kPort = 43001;
    constexpr size_t kBytes = 512 * 1024;

    TcpFixture fx(kPort);
    std::atomic<uint64_t> acks{0};

    // Drive the ACK path hard for a fixed number of rounds (it is the thing
    // this test wants contending): the download itself only takes a few
    // milliseconds, so a "run until stop" thread would barely get going.
    constexpr int kAckRounds = 400;

    // Like a real host: acknowledge everything the engine has emitted so far,
    // otherwise the relay's window gate closes after the first in-flight bytes
    // and the download stops there.
    std::thread acker([&] {
        uint32_t ack = fx.serverIsn + 1;
        size_t scanned = 0;
        for (int i = 0; i < kAckRounds; i++) {
            const auto pkts = fx.out->From(scanned);
            scanned += pkts.size();
            for (const auto& raw : pkts) {
                const auto p = ParseTcpRef(raw);
                if (p.valid && (p.flags & 0x08) && !p.payload.empty()) {
                    ack = p.seq + static_cast<uint32_t>(p.payload.size());
                }
            }
            if (!fx.SendFromHost(fx.clientIsn + 1, 0x10 /*ACK*/, {}, ack)) break;
            acks.fetch_add(1, std::memory_order_relaxed);
        }
    });

    const std::vector<uint8_t> data = PatternBytes(kBytes, 11);
    fx.stream->Feed(data);

    std::vector<uint8_t> got;
    uint32_t expectedSeq = fx.serverIsn + 1;
    size_t processed = 0;
    long long segments = 0;
    // Let the ACK thread run first so its contention overlaps the download
    // rather than trailing it.
    const bool done = WaitForCond(
        [&] {
            const long long s = ValidateDownload(fx.out, processed, expectedSeq, &got);
            if (s > 0) segments += s;
            return got.size() >= data.size();
        },
        10000);
    acker.join();

    if (!done) {
        std::printf("[perf-h3] only %zu of %zu download bytes emitted (%llu acks)\n",
                    got.size(), data.size(), (unsigned long long)acks.load());
    }
    HY_CHECK(done);
    std::printf("[perf-h3] %zu download bytes, %lld segments, %llu ACKs from the packet "
                "thread\n",
                got.size(), segments, (unsigned long long)acks.load());
    // The point of the test: the ACK path hammered conn->mtx while the relay
    // was building segments. Require real contention, not a couple of
    // stragglers - the download is 512 KB, so hundreds of ACKs is a floor.
    HY_CHECK(acks.load() > 100);
    HY_CHECK(segments > 0);
    HY_CHECK_EQ(got.size(), data.size());
    HY_CHECK(got == data);
    std::printf("[perf-h3] %zu download bytes over %lld ACK-contended segments, "
                "seq chain contiguous\n",
                got.size(), segments);
}

// ---------------------------------------------------------------------------
// H5: the IP ID counter is per-thread.
//
// A single shared atomic made every packet (from every relay thread and the
// packet thread) take a locked RMW on the same cache line. Per-thread ranges
// keep that property without the contention - and they must not degenerate
// into a per-thread constant, which would put the same ID into every packet a
// thread builds. This test guards both directions: with four threads each
// building hundreds of packets, no ID may repeat.
// ---------------------------------------------------------------------------
HY_TEST(PerfEngine_IpIdUniqueWithManyThreads) {
    constexpr int kThreads = 4;
    constexpr int kAcksPerThread = 300;

    std::vector<std::shared_ptr<TcpFixture>> fixtures;
    std::vector<std::thread> threads;
    std::mutex collectMu;
    std::vector<uint16_t> ids;

    for (int t = 0; t < kThreads; t++) {
        fixtures.push_back(std::make_shared<TcpFixture>(
            static_cast<uint16_t>(44000 + t), 600000 + static_cast<uint32_t>(t)));
    }
    for (int t = 0; t < kThreads; t++) {
        threads.emplace_back([&, t] {
            auto fx = fixtures[static_cast<size_t>(t)];
            uint32_t seq = fx->clientIsn + 1;
            for (int i = 0; i < kAcksPerThread; i++) {
                // One upload byte per round: a payload makes the engine answer
                // with a packet of its own (a bare ACK produces no output), so
                // every round builds one packet on the relay thread.
                const std::vector<uint8_t> payload = {static_cast<uint8_t>(i & 0xFF)};
                fx->SendFromHost(seq, 0x18, payload);
                seq += static_cast<uint32_t>(payload.size());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            std::vector<uint16_t> local;
            for (const auto& pkt : fx->out->From(0)) {
                if (pkt.size() < 20) continue;
                local.push_back(static_cast<uint16_t>((pkt[4] << 8) | pkt[5]));
            }
            std::lock_guard<std::mutex> lk(collectMu);
            ids.insert(ids.end(), local.begin(), local.end());
        });
    }
    for (auto& th : threads) th.join();

    std::sort(ids.begin(), ids.end());
    const size_t unique = std::unique(ids.begin(), ids.end()) - ids.begin();
    std::printf("[perf-h5] %zu packets from %d threads -> %zu distinct IP IDs\n",
                ids.size(), kThreads, unique);
    HY_CHECK(ids.size() >= static_cast<size_t>(kThreads * kAcksPerThread));
    HY_CHECK_EQ(unique, ids.size());}

// ---------------------------------------------------------------------------
// L1: connection ids must not collide between flows.
//
// The old id was `srcIp ^ dstIp ^ (srcPort << 16 | dstPort)`, and ordinary
// traffic folds onto the same value: 10.0.0.1<->10.0.0.2 and 10.0.0.4<->10.0.0.7
// both XOR to 3 with the same ports. A colliding flow's SYN was then answered
// with the other flow's SYN-ACK and never dialed; its packets were relayed
// into the other flow's session - for TCP that looks like endless
// retransmits, for UDP it delivers datagrams to the wrong target.
//
// The engine now hashes the whole 4-tuple into 64 bits, so these two flows must
// be two independent connections, each with its own stream.
// ---------------------------------------------------------------------------
HY_TEST(PerfEngine_ConnIdCollidingTuplesStaySeparate) {
    // 0x0A000001 ^ 0x0A000002 == 3 and 0x0A000004 ^ 0x0A000007 == 3.
    constexpr uint32_t kA_src = 0x0A000001, kA_dst = 0x0A000002;
    constexpr uint32_t kB_src = 0x0A000004, kB_dst = 0x0A000007;
    constexpr uint16_t kSharedPort = 1000;
    constexpr uint16_t kDstPort = 2000;

    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<PerfMockClient>();
    engine->SetClient(client);

    // Both connections live in ONE engine: a collision only matters inside the
    // same session table.
    auto fxA = std::make_shared<TcpFixture>(engine, client, kSharedPort, kA_src, kA_dst,
                                            kDstPort, 100000);
    auto fxB = std::make_shared<TcpFixture>(engine, client, kSharedPort, kB_src, kB_dst,
                                            kDstPort, 200000);

    HY_CHECK_EQ(client->streams.size(), (size_t)2);
    HY_CHECK(fxA->stream != nullptr);
    HY_CHECK(fxB->stream != nullptr);
    HY_CHECK(fxA->stream != fxB->stream);
    HY_CHECK_EQ(engine->GetStats().totalConnections, (uint64_t)2);

    // Each flow's upload must land on its own stream, not on the other's.
    fxA->stream->TakeWrittenChunks();
    fxB->stream->TakeWrittenChunks();
    const std::vector<uint8_t> markerA = {'A', '-', 'd', 'a', 't', 'a'};
    const std::vector<uint8_t> markerB = {'B', '-', 'd', 'a', 't', 'a'};
    HY_CHECK(fxA->SendFromHost(fxA->clientIsn + 1, 0x18, markerA));
    HY_CHECK(fxB->SendFromHost(fxB->clientIsn + 1, 0x18, markerB));

    std::vector<uint8_t> gotA, gotB;
    const bool ok = WaitForCond(
        [&] {
            for (auto& c : fxA->stream->TakeWrittenChunks()) gotA.insert(gotA.end(),
                                                                        c.begin(), c.end());
            for (auto& c : fxB->stream->TakeWrittenChunks()) gotB.insert(gotB.end(),
                                                                        c.begin(), c.end());
            return gotA.size() >= markerA.size() && gotB.size() >= markerB.size();
        },
        3000);
    if (!ok) {
        std::printf("[perf-l1] A got %zu/%zu bytes, B got %zu/%zu bytes\n", gotA.size(),
                    markerA.size(), gotB.size(), markerB.size());
    }
    HY_CHECK(ok);
    HY_CHECK(gotA == markerA);
    HY_CHECK(gotB == markerB);

    // Join the relay workers BEFORE the fixtures (and with them the sendBack
    // lambdas the read loop still calls) go out of scope.
    engine->Close();
}

} // namespace
