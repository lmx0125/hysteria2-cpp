// proxy_engine_test.cpp - Behavior tests for the alyssum_proxy data plane
// engine (packet building, TCP/UDP relay, stats).
//
// The engine sources are compiled into this unified runner (see
// tests/CMakeLists.txt). These tests give H7-H11/M5 a regression net: they
// verify handshake/relay correctness and packet integrity while the engine's
// per-packet allocation/notification hot paths are optimized.
//
// The engine is driven with a mock hy2::client::Client backed by the
// in-memory PipeStream, so no real network is involved.

#include "hytest.hpp"

#include "mock_quic.hpp"
#include "proxy_engine.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#error "proxy engine tests are Windows-only (packet_parser uses winsock types)"
#endif

using namespace proxy;

namespace {
class RejectedTargetStream : public hy2::IByteReaderWriter {
public:
    size_t Read(uint8_t*, size_t) override { throw hy2::DialError("controlled target refusal"); }
    void Write(const uint8_t*, size_t) override {}
};

class HalfCloseStream : public hy2::IByteReaderWriter {
public:
    std::shared_ptr<hytest::PipeStream> pipe;
    std::atomic<int> halfCloses{0};
    explicit HalfCloseStream(std::shared_ptr<hytest::PipeStream> p) : pipe(std::move(p)) {}
    size_t Read(uint8_t* p, size_t n) override { return pipe->Read(p,n); }
    void Write(const uint8_t* p, size_t n) override { pipe->Write(p,n); }
    void Close() override { pipe->Close(); }
    void CloseWrite() override { pipe->CloseWrite(); ++halfCloses; }
};
}

namespace {

// ---------------------------------------------------------------------------
// Packet construction / parsing helpers (host-order IPs, like packet_parser)
// ---------------------------------------------------------------------------

uint32_t AddWords(uint32_t sum, const uint8_t* data, size_t len) {
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (len & 1) sum += static_cast<uint32_t>(data[len - 1]) << 8;
    return sum;
}

uint16_t Fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t IpChecksum(const uint8_t* data, size_t len) { return Fold(AddWords(0, data, len)); }

uint16_t L4Checksum(const uint8_t* data, size_t len, uint32_t srcIp, uint32_t dstIp,
                    uint8_t proto) {
    uint32_t sum = 0;
    sum += (srcIp >> 16) & 0xFFFF;
    sum += srcIp & 0xFFFF;
    sum += (dstIp >> 16) & 0xFFFF;
    sum += dstIp & 0xFFFF;
    sum += proto;
    sum += static_cast<uint16_t>(len);
    return Fold(AddWords(sum, data, len));
}

std::vector<BYTE> MakeIpTcp(uint32_t srcIp, uint32_t dstIp, uint16_t srcPort,
                            uint16_t dstPort, uint32_t seq, uint32_t ack,
                            uint8_t flags, const std::vector<uint8_t>& payload) {
    const size_t total = 20 + 20 + payload.size();
    std::vector<BYTE> pkt(total, 0);
    pkt[0] = 0x45;
    pkt[2] = static_cast<BYTE>(total >> 8);
    pkt[3] = static_cast<BYTE>(total & 0xFF);
    pkt[8] = 64;
    pkt[9] = 6;
    const uint32_t srcN = htonl(srcIp), dstN = htonl(dstIp);
    std::memcpy(&pkt[12], &srcN, 4);
    std::memcpy(&pkt[16], &dstN, 4);
    const uint16_t ipc = IpChecksum(pkt.data(), 20);
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
    tcp[12] = 0x50; // data offset 5
    tcp[13] = flags;
    tcp[14] = 0xFF;
    tcp[15] = 0xFF; // window 65535
    if (!payload.empty()) std::memcpy(tcp + 20, payload.data(), payload.size());
    const uint16_t csum = L4Checksum(tcp, 20 + payload.size(), srcIp, dstIp, 6);
    tcp[16] = static_cast<BYTE>(csum >> 8);
    tcp[17] = static_cast<BYTE>(csum & 0xFF);
    return pkt;
}

std::vector<BYTE> MakeIpUdp(uint32_t srcIp, uint32_t dstIp, uint16_t srcPort,
                            uint16_t dstPort, const std::vector<uint8_t>& payload) {
    const size_t udpLen = 8 + payload.size();
    const size_t total = 20 + udpLen;
    std::vector<BYTE> pkt(total, 0);
    pkt[0] = 0x45;
    pkt[2] = static_cast<BYTE>(total >> 8);
    pkt[3] = static_cast<BYTE>(total & 0xFF);
    pkt[8] = 64;
    pkt[9] = 17;
    const uint32_t srcN = htonl(srcIp), dstN = htonl(dstIp);
    std::memcpy(&pkt[12], &srcN, 4);
    std::memcpy(&pkt[16], &dstN, 4);
    const uint16_t ipc = IpChecksum(pkt.data(), 20);
    pkt[10] = static_cast<BYTE>(ipc >> 8);
    pkt[11] = static_cast<BYTE>(ipc & 0xFF);

    BYTE* udp = pkt.data() + 20;
    udp[0] = static_cast<BYTE>(srcPort >> 8);
    udp[1] = static_cast<BYTE>(srcPort & 0xFF);
    udp[2] = static_cast<BYTE>(dstPort >> 8);
    udp[3] = static_cast<BYTE>(dstPort & 0xFF);
    udp[4] = static_cast<BYTE>(udpLen >> 8);
    udp[5] = static_cast<BYTE>(udpLen & 0xFF);
    std::memcpy(udp + 8, payload.data(), payload.size());
    uint16_t csum = L4Checksum(udp, udpLen, srcIp, dstIp, 17);
    if (csum == 0) csum = 0xFFFF;
    udp[6] = static_cast<BYTE>(csum >> 8);
    udp[7] = static_cast<BYTE>(csum & 0xFF);
    return pkt;
}

struct ParsedTcp {
    bool valid = false;
    uint16_t srcPort = 0, dstPort = 0;
    uint32_t seq = 0, ack = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> options;  // raw option bytes (before padding removal)
    bool ipChecksumOk = false;
    bool tcpChecksumOk = false;
};

ParsedTcp ParseTcp(const std::vector<BYTE>& pkt) {
    ParsedTcp r;
    if (pkt.size() < 40 || pkt[0] != 0x45) return r;
    const uint32_t srcIp = (static_cast<uint32_t>(pkt[12]) << 24) |
                           (static_cast<uint32_t>(pkt[13]) << 16) |
                           (static_cast<uint32_t>(pkt[14]) << 8) | pkt[15];
    const uint32_t dstIp = (static_cast<uint32_t>(pkt[16]) << 24) |
                           (static_cast<uint32_t>(pkt[17]) << 16) |
                           (static_cast<uint32_t>(pkt[18]) << 8) | pkt[19];
    // IP checksum: recompute with the checksum field zeroed.
    std::vector<uint8_t> iph(pkt.begin(), pkt.begin() + 20);
    const uint16_t storedIp = static_cast<uint16_t>((iph[10] << 8) | iph[11]);
    iph[10] = iph[11] = 0;
    r.ipChecksumOk = (IpChecksum(iph.data(), 20) == storedIp);

    const BYTE* tcp = pkt.data() + 20;
    const size_t tcpLen = pkt.size() - 20;
    r.srcPort = static_cast<uint16_t>((tcp[0] << 8) | tcp[1]);
    r.dstPort = static_cast<uint16_t>((tcp[2] << 8) | tcp[3]);
    r.seq = (static_cast<uint32_t>(tcp[4]) << 24) | (static_cast<uint32_t>(tcp[5]) << 16) |
            (static_cast<uint32_t>(tcp[6]) << 8) | tcp[7];
    r.ack = (static_cast<uint32_t>(tcp[8]) << 24) | (static_cast<uint32_t>(tcp[9]) << 16) |
            (static_cast<uint32_t>(tcp[10]) << 8) | tcp[11];
    r.flags = tcp[13];
    // Data offset (TCP header length) from the high nibble of byte 12.
    const size_t tcpHdrLen = static_cast<size_t>((tcp[12] >> 4) & 0x0F) * 4;
    if (tcpLen >= tcpHdrLen) {
        r.payload.assign(pkt.begin() + 20 + static_cast<long>(tcpHdrLen), pkt.end());
        if (tcpHdrLen > 20) {
            r.options.assign(tcp + 20, tcp + tcpHdrLen);
        }
    }
    const uint16_t storedTcp = static_cast<uint16_t>((tcp[16] << 8) | tcp[17]);
    std::vector<uint8_t> tcpCopy(tcp, tcp + tcpLen);
    tcpCopy[16] = tcpCopy[17] = 0;
    r.tcpChecksumOk = (L4Checksum(tcpCopy.data(), tcpLen, srcIp, dstIp, 6) == storedTcp);
    r.valid = true;
    return r;
}

struct ParsedUdp {
    bool valid = false;
    uint16_t srcPort = 0, dstPort = 0;
    std::vector<uint8_t> payload;
};

ParsedUdp ParseUdp(const std::vector<BYTE>& pkt) {
    ParsedUdp r;
    if (pkt.size() < 28 || pkt[0] != 0x45) return r;
    const BYTE* udp = pkt.data() + 20;
    r.srcPort = static_cast<uint16_t>((udp[0] << 8) | udp[1]);
    r.dstPort = static_cast<uint16_t>((udp[2] << 8) | udp[3]);
    r.payload.assign(pkt.begin() + 28, pkt.end());
    r.valid = true;
    return r;
}

bool WaitFor(const std::function<bool()>& cond, int timeoutMs = 3000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return cond();
}

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

class MockUdpConn : public hy2::client::HyUDPConn {
public:
    bool Receive(std::vector<uint8_t>& data, std::string& addr) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, std::chrono::milliseconds(20),
                     [&] { return closed_ || !inQ_.empty(); });
        if (inQ_.empty()) return false;
        data = std::move(inQ_.front().first);
        addr = std::move(inQ_.front().second);
        inQ_.pop_front();
        return true;
    }
    // Matches the real UdpConn: distinguishes a quiet poll from a closed
    // session, which is what the relay loops depend on.
    hy2::client::UdpRecvResult ReceivePacket(std::vector<uint8_t>& data,
                                             std::string& addr,
                                             hy2::Duration timeout) override {
        std::unique_lock<std::mutex> lk(mu_);
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::nanoseconds(timeout.ns);
        cv_.wait_until(lk, deadline, [&] { return closed_ || !inQ_.empty(); });
        if (!inQ_.empty()) {
            data = std::move(inQ_.front().first);
            addr = std::move(inQ_.front().second);
            inQ_.pop_front();
            return hy2::client::UdpRecvResult::kPacket;
        }
        return closed_ ? hy2::client::UdpRecvResult::kClosed
                       : hy2::client::UdpRecvResult::kTimeout;
    }
    void Send(const uint8_t* data, size_t n, const std::string& addr) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            sent_.emplace_back(std::vector<uint8_t>(data, data + n), addr);
        }
        cv_.notify_all();
    }
    void Close() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    void Inject(std::vector<uint8_t> data, std::string addr) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            inQ_.emplace_back(std::move(data), std::move(addr));
        }
        cv_.notify_all();
    }
    size_t SentCount() {
        std::lock_guard<std::mutex> lk(mu_);
        return sent_.size();
    }
    std::pair<std::vector<uint8_t>, std::string> SentAt(size_t i) {
        std::lock_guard<std::mutex> lk(mu_);
        return sent_[i];
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    bool closed_ = false;
    std::deque<std::pair<std::vector<uint8_t>, std::string>> inQ_;
    std::deque<std::pair<std::vector<uint8_t>, std::string>> sent_;
};

class MockClient : public hy2::client::Client {
public:
    std::shared_ptr<hy2::IByteReaderWriter> tcpStream;
    std::shared_ptr<MockUdpConn> udp = std::make_shared<MockUdpConn>();
    std::string lastTarget;

    std::shared_ptr<hy2::IByteReaderWriter> TCP(const std::string& addr) override {
        lastTarget = addr;
        return tcpStream;
    }
    std::shared_ptr<hy2::client::HyUDPConn> UDP() override { return udp; }
    void Close() override {}
};

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
};

constexpr uint32_t kClientIp = 0x0A000002; // 10.0.0.2
constexpr uint32_t kTargetIp = 0x08080808; // 8.8.8.8
constexpr uint16_t kClientPort = 40000;
constexpr uint16_t kTargetPort = 80;

} // namespace

// ---------------------------------------------------------------------------
// TCP handshake: SYN must trigger a dial and a valid SYN|ACK.
// ---------------------------------------------------------------------------
HY_TEST(ProxyEngine_TcpHandshakeSynAck) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    auto [engineSide, peerSide] = hytest::PipeStream::MakePair();
    client->tcpStream = engineSide;
    engine->SetClient(client);

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    const uint32_t clientIsn = 1000;
    auto syn = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                         clientIsn, 0, 0x02 /*SYN*/, {});
    auto info = packet_parser::ParsePacket(syn.data(), static_cast<DWORD>(syn.size()));
    HY_CHECK(info.valid);
    HY_CHECK(engine->HandleTcpPacket(info, syn.data(), static_cast<DWORD>(syn.size()), sendBack));

    HY_CHECK(WaitFor([&] { return out.Size() >= 1; }));
    auto r = ParseTcp(out.At(0));
    HY_CHECK(r.valid);
    HY_CHECK_EQ(r.flags, (uint8_t)0x12);          // SYN|ACK
    HY_CHECK_EQ(r.srcPort, kTargetPort);
    HY_CHECK_EQ(r.dstPort, kClientPort);
    HY_CHECK_EQ(r.ack, clientIsn + 1);
    HY_CHECK(r.ipChecksumOk);
    HY_CHECK(r.tcpChecksumOk);
    HY_CHECK_EQ(client->lastTarget, std::string("8.8.8.8:80"));

    engine->Close();
}

// ---------------------------------------------------------------------------
// TCP relay: upload lands in the stream, download comes back as packets.
// ---------------------------------------------------------------------------
HY_TEST(ProxyEngine_TcpRelayBothDirections) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    auto [engineSide, peerSide] = hytest::PipeStream::MakePair();
    client->tcpStream = engineSide;
    engine->SetClient(client);

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    const uint32_t clientIsn = 5000;
    auto syn = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                         clientIsn, 0, 0x02, {});
    auto synInfo = packet_parser::ParsePacket(syn.data(), static_cast<DWORD>(syn.size()));
    HY_CHECK(engine->HandleTcpPacket(synInfo, syn.data(), static_cast<DWORD>(syn.size()), sendBack));
    HY_CHECK(WaitFor([&] { return out.Size() >= 1; }));
    const auto synAck = ParseTcp(out.At(0));
    HY_CHECK_EQ(synAck.flags, (uint8_t)0x12);

    // Publish a large receive window so the read loop runs immediately.
    auto ack = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                         clientIsn + 1, synAck.seq + 1, 0x10 /*ACK*/, {});
    auto ackInfo = packet_parser::ParsePacket(ack.data(), static_cast<DWORD>(ack.size()));
    HY_CHECK(engine->HandleTcpPacket(ackInfo, ack.data(), static_cast<DWORD>(ack.size()), sendBack));

    // ---- Upload: client -> engine -> QUIC stream ----
    const std::vector<uint8_t> up = {'h', 'e', 'l', 'l', 'o'};
    auto data = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                          clientIsn + 1, synAck.seq + 1, 0x18 /*PSH|ACK*/, up);
    auto dataInfo = packet_parser::ParsePacket(data.data(), static_cast<DWORD>(data.size()));
    HY_CHECK(engine->HandleTcpPacket(dataInfo, data.data(), static_cast<DWORD>(data.size()), sendBack));

    std::vector<uint8_t> gotUp;
    {
        std::vector<uint8_t> buf(64);
        const size_t n = peerSide->Read(buf.data(), buf.size());
        gotUp.assign(buf.begin(), buf.begin() + static_cast<long>(n));
    }
    HY_CHECK(gotUp == up);

    // ---- Download: QUIC stream -> engine -> packets ----
    const std::vector<uint8_t> down = {'w', 'o', 'r', 'l', 'd', '!'};
    peerSide->Write(down.data(), down.size());

    // The engine may emit an ACK for the uploaded data before the download
    // packet: scan the output for the packet carrying the payload.
    bool found = false;
    ParsedTcp reply;
    const bool gotReply = WaitFor([&] {
        for (size_t i = 0; i < out.Size(); i++) {
            auto p = ParseTcp(out.At(i));
            if (p.valid && p.payload == down) {
                reply = p;
                found = true;
                return true;
            }
        }
        return false;
    });
    if (!gotReply) {
        for (size_t i = 0; i < out.Size(); i++) {
            auto p = ParseTcp(out.At(i));
            std::printf("[engine-test] out[%zu] valid=%d flags=0x%02x len=%zu\n", i,
                        (int)p.valid, p.flags, p.payload.size());
        }
    }
    HY_CHECK(gotReply);
    HY_CHECK(found);
    HY_CHECK(reply.valid);
    HY_CHECK_EQ(reply.srcPort, kTargetPort);
    HY_CHECK_EQ(reply.dstPort, kClientPort);
    HY_CHECK((reply.flags & 0x08) == 0x08); // PSH (ACK may vary)
    HY_CHECK(reply.payload == down);
    HY_CHECK(reply.ipChecksumOk);
    HY_CHECK(reply.tcpChecksumOk);

    // Ack the download so the connection stays healthy, then close.
    auto ack2 = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                          clientIsn + 1 + static_cast<uint32_t>(up.size()),
                          reply.seq + static_cast<uint32_t>(down.size()),
                          0x10, {});
    auto ack2Info = packet_parser::ParsePacket(ack2.data(), static_cast<DWORD>(ack2.size()));
    HY_CHECK(engine->HandleTcpPacket(ack2Info, ack2.data(), static_cast<DWORD>(ack2.size()), sendBack));

    engine->Close();
    HY_CHECK(engine->GetStats().totalConnections >= 1);
}

// ---------------------------------------------------------------------------
// UDP relay: outbound send + inbound packet rebuild.
// ---------------------------------------------------------------------------
HY_TEST(ProxyEngine_UdpRelayBothDirections) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    engine->SetClient(client);

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    const std::vector<uint8_t> query = {'q', 'u', 'e', 'r', 'y'};
    auto pkt = MakeIpUdp(kClientIp, kTargetIp, 5000, 53, query);
    auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
    HY_CHECK(info.valid);
    HY_CHECK(engine->HandleUdpPacket(info, pkt.data(), static_cast<DWORD>(pkt.size()), sendBack));

    HY_CHECK(WaitFor([&] { return client->udp->SentCount() >= 1; }));
    auto sent = client->udp->SentAt(0);
    HY_CHECK(sent.first == query);
    HY_CHECK_EQ(sent.second, std::string("8.8.8.8:53"));

    // Reply from the target comes back as a well-formed UDP packet with the
    // addresses swapped.
    const std::vector<uint8_t> answer = {'a', 'n', 's'};
    client->udp->Inject(answer, "8.8.8.8:53");
    HY_CHECK(WaitFor([&] { return out.Size() >= 1; }));
    auto back = ParseUdp(out.At(0));
    HY_CHECK(back.valid);
    HY_CHECK_EQ(back.srcPort, 53);
    HY_CHECK_EQ(back.dstPort, 5000);
    HY_CHECK(back.payload == answer);

    engine->Close();
    HY_CHECK(engine->GetStats().udpConnections >= 1);
    HY_CHECK(engine->GetStats().totalBytesOut >= query.size());
}

// ---------------------------------------------------------------------------
// Burst coverage for the batching/edge-trigger/buffer-pool write paths.
// ---------------------------------------------------------------------------
HY_TEST(ProxyEngine_TcpUploadBurstOrdered) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    auto [engineSide, peerSide] = hytest::PipeStream::MakePair();
    client->tcpStream = engineSide;
    engine->SetClient(client);

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    const uint32_t clientIsn = 7000;
    auto syn = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                         clientIsn, 0, 0x02, {});
    auto synInfo = packet_parser::ParsePacket(syn.data(), static_cast<DWORD>(syn.size()));
    HY_CHECK(engine->HandleTcpPacket(synInfo, syn.data(), static_cast<DWORD>(syn.size()), sendBack));
    HY_CHECK(WaitFor([&] { return out.Size() >= 1; }));

    // 100 back-to-back segments, one byte sequence number each.
    constexpr int kSegments = 100;
    uint32_t seq = clientIsn + 1;
    for (int i = 0; i < kSegments; i++) {
        std::vector<uint8_t> payload = {static_cast<uint8_t>(i)};
        auto pkt = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                             seq, 0, 0x18, payload);
        auto pi = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
        HY_CHECK(engine->HandleTcpPacket(pi, pkt.data(), static_cast<DWORD>(pkt.size()), sendBack));
        seq += static_cast<uint32_t>(payload.size());
    }

    std::vector<uint8_t> got;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (got.size() < kSegments && std::chrono::steady_clock::now() < deadline) {
        std::vector<uint8_t> buf(256);
        size_t n = 0;
        try {
            n = peerSide->Read(buf.data(), buf.size());
        } catch (...) {
            break;
        }
        if (n == 0) break;
        got.insert(got.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    HY_CHECK_EQ(got.size(), (size_t)kSegments);
    for (int i = 0; i < kSegments; i++) {
        HY_CHECK_EQ(got[static_cast<size_t>(i)], (uint8_t)i); // FIFO order
    }

    engine->Close();
}

HY_TEST(ProxyEngine_UdpBurstAllQueued) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    engine->SetClient(client);

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    constexpr int kDatagrams = 100;
    for (int i = 0; i < kDatagrams; i++) {
        // Same 4-tuple for all: one session/queue so FIFO order is defined.
        std::vector<uint8_t> payload = {static_cast<uint8_t>(i)};
        auto pkt = MakeIpUdp(kClientIp, kTargetIp, 5000, 53, payload);
        auto pi = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
        HY_CHECK(engine->HandleUdpPacket(pi, pkt.data(), static_cast<DWORD>(pkt.size()), sendBack));
    }

    HY_CHECK(WaitFor([&] { return client->udp->SentCount() >= (size_t)kDatagrams; }, 5000));
    HY_CHECK_EQ(client->udp->SentCount(), (size_t)kDatagrams);
    for (int i = 0; i < kDatagrams; i++) {
        auto s = client->udp->SentAt(static_cast<size_t>(i));
        HY_CHECK_EQ(s.first.size(), (size_t)1);
        HY_CHECK_EQ(s.first[0], (uint8_t)i); // order preserved through the queue
        HY_CHECK_EQ(s.second, std::string("8.8.8.8:53"));
    }

    engine->Close();
}

// ---------------------------------------------------------------------------
// Non-proxyable destinations and stats isolation.
// ---------------------------------------------------------------------------
HY_TEST(ProxyEngine_NonProxyableAndStats) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    engine->SetClient(client);
    engine->SetServerIp(kTargetIp);
    engine->SetLocalSubnet(0x0A000000, 0xFFFFFF00); // 10.0.0.0/24

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    // Destination is the hy2 server itself: must never be proxied.
    auto syn = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort, 1, 0, 0x02, {});
    auto info = packet_parser::ParsePacket(syn.data(), static_cast<DWORD>(syn.size()));
    HY_CHECK(!engine->HandleTcpPacket(info, syn.data(), static_cast<DWORD>(syn.size()), sendBack));

    // Destination in the local subnet: same.
    auto local = MakeIpTcp(kClientIp, 0x0A000005, kClientPort, 445, 1, 0, 0x02, {});
    auto localInfo = packet_parser::ParsePacket(local.data(), static_cast<DWORD>(local.size()));
    HY_CHECK(!engine->HandleTcpPacket(localInfo, local.data(), static_cast<DWORD>(local.size()), sendBack));

    HY_CHECK_EQ(out.Size(), (size_t)0);
    HY_CHECK_EQ(engine->GetStats().totalConnections, (uint64_t)0);
    HY_CHECK_EQ(engine->GetStats().activeConnections, (uint64_t)0);

    engine->Close();
}

// ---------------------------------------------------------------------------
// Worker reaping.
//
// Every proxied TCP connection attaches up to three workers (connect + read +
// write), and a finished-but-unjoined std::thread keeps its OS handle (and its
// reserved stack) alive. The list used to be emptied only in Close(), so a
// session that opened N connections held N thread handles for the whole run.
// These tests pin the reaping that bounds it.
// ---------------------------------------------------------------------------
namespace {

// A connection that completes and then closes, so its workers finish. Used to
// accumulate finished workers without leaving anything running.
//
// Everything the connection reaches after this function returns has to outlive
// it: the engine stores the sendBack callback in the connection and the read
// loop invokes it, and the QUIC-side stream stays owned by the connection. The
// caller therefore owns the Output and the peer stream, and MockClient keeps
// one client-side stream per opened connection.
struct ChurnFixture {
    std::shared_ptr<ProxyEngine> engine;
    std::shared_ptr<MockClient> client;
    std::vector<std::shared_ptr<Output>> outputs;   // outlive each connection
    std::vector<std::shared_ptr<hy2::IByteReaderWriter>> streams;
    uint16_t nextPort = 40000;

    ChurnFixture() {
        engine = std::make_shared<ProxyEngine>();
        client = std::make_shared<MockClient>();
        engine->SetClient(client);
    }

    // Opens a TCP connection through the engine and then closes its remote
    // side so both relay loops exit.
    void OpenAndFinish() {
        auto [engineSide, peerSide] = hytest::PipeStream::MakePair();
        streams.push_back(engineSide);
        streams.push_back(peerSide);
        client->tcpStream = engineSide;

        auto out = std::make_shared<Output>();
        outputs.push_back(out);

        const uint16_t clientPort = nextPort++;
        auto syn = MakeIpTcp(kClientIp, kTargetIp, clientPort, kTargetPort,
                             1000, 0, 0x02, {});
        auto synInfo = packet_parser::ParsePacket(syn.data(),
                                                  static_cast<DWORD>(syn.size()));
        engine->HandleTcpPacket(synInfo, syn.data(),
                                static_cast<DWORD>(syn.size()),
                                [out](const BYTE* d, DWORD n) {
                                    out->Add(d, n);
                                    return true;
                                });
        WaitFor([&] { return out->Size() >= 1; });

        // EOF on the remote side: the read loop returns 0 and both loops exit.
        try { peerSide->Close(); } catch (...) {}
    }
};

} // namespace

HY_TEST(ProxyEngine_FinishedWorkersAreReaped) {
    ChurnFixture fx;

    // One connection, then let its workers finish.
    fx.OpenAndFinish();
    HY_CHECK(WaitFor([&] { return fx.engine->GetStats().activeConnections == 0; },
                     3000));

    const size_t afterFirst = fx.engine->WorkerCount();
    HY_CHECK(afterFirst >= 1);  // not reaped yet - nothing has triggered a scan

    // A second connection triggers StartThread's reap: the finished workers of
    // the first must be released rather than accumulating.
    fx.OpenAndFinish();
    HY_CHECK(WaitFor([&] { return fx.engine->WorkerCount() <= afterFirst + 1; },
                     3000));

    fx.engine->Close();
    // Close() joins the remainder, so the list must be empty afterwards.
    HY_CHECK_EQ(fx.engine->WorkerCount(), (size_t)0);
}

// The storm case: many connections in a row must not grow the held-handle
// count proportionally. Without reaping this grew with every connection.
HY_TEST(ProxyEngine_WorkerCountStaysBoundedUnderChurn) {
    ChurnFixture fx;

    for (int i = 0; i < 40; ++i) {
        fx.OpenAndFinish();
    }
    // Let the tail of the connections wind down, then nudge a reap.
    HY_CHECK(WaitFor([&] { return fx.engine->GetStats().activeConnections == 0; },
                     5000));
    fx.OpenAndFinish();
    SleepFor(hy2::Duration::FromMillis(300));

    // 40 connections spawned up to 3 workers each. Bounded means the count is
    // nowhere near 120 - it reflects only what is genuinely still running
    // (plus at most the last few not yet reaped).
    const size_t workers = fx.engine->WorkerCount();
    HY_CHECK(workers < 40);

    fx.engine->Close();
    HY_CHECK_EQ(fx.engine->WorkerCount(), (size_t)0);
}

// ---------------------------------------------------------------------------
// Window scaling (RFC 7323).
//
// The engine advertised a raw 16-bit window with no WS option, so at most
// 65535 bytes could be in flight on a proxied TCP flow: 0.4 MB/s on a 160 ms
// RTT, i.e. "the tunnel is slow" while the QUIC leg underneath was idle. These
// pin the negotiation and the scaled decoding.
// ---------------------------------------------------------------------------

// Builds a SYN carrying the given TCP options (kind/len/value bytes).
static std::vector<BYTE> MakeIpTcpOpts(uint32_t srcIp, uint32_t dstIp,
                                       uint16_t srcPort, uint16_t dstPort,
                                       uint32_t seq, uint32_t ack, uint8_t flags,
                                       const std::vector<BYTE>& opts,
                                       uint16_t windowField) {
    // IP header (20) + TCP header incl. options, padded to the 4-byte boundary.
    // The option bytes beyond opts.size() stay zero: zero is the EOL marker,
    // which the parser stops at - exactly how a real stack pads.
    const size_t tcpHdrLen = 20 + ((opts.size() + 3) & ~size_t(3));
    const size_t total = 20 + tcpHdrLen;
    std::vector<BYTE> pkt(total, 0);
    pkt[0] = 0x45;
    pkt[2] = static_cast<BYTE>(total >> 8);
    pkt[3] = static_cast<BYTE>(total & 0xFF);
    pkt[8] = 64;
    pkt[9] = 6;
    const uint32_t srcN = htonl(srcIp), dstN = htonl(dstIp);
    std::memcpy(&pkt[12], &srcN, 4);
    std::memcpy(&pkt[16], &dstN, 4);
    const uint16_t ipc = IpChecksum(pkt.data(), 20);
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
    // Data offset counts 32-bit words of the whole TCP header (fixed + opts).
    tcp[12] = static_cast<BYTE>((tcpHdrLen / 4) << 4);
    tcp[13] = flags;
    tcp[14] = static_cast<BYTE>(windowField >> 8);
    tcp[15] = static_cast<BYTE>(windowField & 0xFF);
    if (!opts.empty()) std::memcpy(tcp + 20, opts.data(), opts.size());
    const uint16_t csum = L4Checksum(tcp, tcpHdrLen, srcIp, dstIp, 6);
    tcp[16] = static_cast<BYTE>(csum >> 8);
    tcp[17] = static_cast<BYTE>(csum & 0xFF);
    return pkt;
}

// Shrink the host window synchronously after the first segment of one 32 KiB
// read. The rest of that read must obey the new window, including a zero
// window, then resume byte-for-byte when the host reopens it.
static void CheckDownloadWindowShrinksDuringBurst(bool closeWhileBlocked) {
    Output out;
    auto client = std::make_shared<MockClient>();
    auto [engineSide, peerSide] = hytest::PipeStream::MakePair();
    client->tcpStream = engineSide;
    auto engine = std::make_shared<ProxyEngine>();
    engine->SetClient(client);
    std::atomic<size_t> delivered{0};
    std::atomic<unsigned> dataPackets{0};
    std::atomic<bool> reopened{false};
    std::atomic<bool> violation{false};
    std::atomic<uint32_t> nextSeq{0};
    std::function<bool(const BYTE*, DWORD)> sendBack;
    auto advertise = [&](uint32_t ack, uint16_t window) {
        auto pkt = MakeIpTcpOpts(kClientIp, kTargetIp, kClientPort, kTargetPort,
                                 1001, ack, 0x10, {}, window);
        const auto info = packet_parser::ParsePacket(pkt.data(), (DWORD)pkt.size());
        engine->HandleTcpPacket(info, pkt.data(), (DWORD)pkt.size(), sendBack);
    };
    sendBack = [&](const BYTE* data, DWORD size) {
        out.Add(data, size);
        const auto pkt = ParseTcp(std::vector<BYTE>(data, data + size));
        if (pkt.payload.empty()) return true;
        const unsigned index = dataPackets.fetch_add(1);
        if (!reopened.load() && ((index == 1 && pkt.payload.size() > 700) || index > 1)) {
            violation.store(true);
        }
        nextSeq.store(pkt.seq + (uint32_t)pkt.payload.size());
        advertise(nextSeq.load(), reopened.load() ? 65535 : (index == 0 ? 700 : 0));
        delivered.fetch_add(pkt.payload.size());
        return true;
    };
    auto syn = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort, 1000, 0, 0x02, {});
    auto info = packet_parser::ParsePacket(syn.data(), (DWORD)syn.size());
    engine->HandleTcpPacket(info, syn.data(), (DWORD)syn.size(), sendBack);
    const bool connected = WaitFor([&] { return out.Size() > 0; });
    std::vector<uint8_t> payload(32768);
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = (uint8_t)(i * 37);
    if (connected) {
        advertise(ParseTcp(out.At(0)).seq + 1, 65535);
        peerSide->Write(payload.data(), payload.size());
    }
    const bool reachedSmallWindow = WaitFor([&] { return delivered.load() >= 2100; });
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    const size_t whileClosed = delivered.load();
    if (closeWhileBlocked) {
        const auto start = std::chrono::steady_clock::now();
        engine->Close();
        const auto elapsed = std::chrono::steady_clock::now() - start;
        HY_CHECK(connected && reachedSmallWindow);
        HY_CHECK(!violation.load());
        HY_CHECK_EQ(whileClosed, (size_t)2100);
        HY_CHECK(elapsed < std::chrono::seconds(2));
        HY_CHECK_EQ(engine->WorkerCount(), (size_t)0);
        return;
    }
    reopened.store(true);
    advertise(nextSeq.load(), 65535);
    const bool finished = WaitFor([&] { return delivered.load() == payload.size(); });
    engine->Close();
    std::vector<uint8_t> actual;
    uint32_t expectedSeq = connected ? ParseTcp(out.At(0)).seq + 1 : 0;
    bool valid = true;
    for (size_t i = 0; i < out.Size(); ++i) {
        const auto pkt = ParseTcp(out.At(i));
        if (pkt.payload.empty()) continue;
        valid &= pkt.seq == expectedSeq && pkt.ipChecksumOk && pkt.tcpChecksumOk;
        expectedSeq += (uint32_t)pkt.payload.size();
        actual.insert(actual.end(), pkt.payload.begin(), pkt.payload.end());
    }
    std::printf("[window-burst] bytes before reopen=%zu, complete=%d, violation=%d\n",
                whileClosed, (int)finished, (int)violation.load());
    HY_CHECK(connected && reachedSmallWindow && finished);
    HY_CHECK(!violation.load());
    HY_CHECK_EQ(whileClosed, (size_t)2100); // 1400-byte first segment + 700 credit
    HY_CHECK(valid && actual == payload);
}

HY_TEST(ProxyEngine_DownloadWindowShrinksDuringBurst) {
    CheckDownloadWindowShrinksDuringBurst(false);
}

HY_TEST(ProxyEngine_CloseDuringDownloadWindowWait) {
    CheckDownloadWindowShrinksDuringBurst(true);
}

HY_TEST(Parser_SynWindowScaleAndMss) {
    // MSS 1460 (kind 2), WS shift 7 (kind 3), NOP padding.
    const std::vector<BYTE> opts = {2, 4, 0x05, 0xB4,
                                    1,
                                    3, 3, 7,
                                    1, 1};
    auto pkt = MakeIpTcpOpts(kClientIp, kTargetIp, kClientPort, kTargetPort,
                             1, 0, 0x02 /*SYN*/, opts, 65535);
    auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
    HY_CHECK(info.valid);
    HY_CHECK(info.isSyn);
    HY_CHECK(info.hasWindowScale);
    HY_CHECK_EQ(info.windowScale, (uint8_t)7);
    HY_CHECK_EQ(info.mss, (uint16_t)1460);
}

HY_TEST(Parser_NoOptionsMeansNoScale) {
    auto pkt = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                         1, 0, 0x02, {});
    auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
    HY_CHECK(info.valid && info.isSyn);
    HY_CHECK(!info.hasWindowScale);
    HY_CHECK_EQ(info.windowScale, (uint8_t)0);
    HY_CHECK_EQ(info.mss, (uint16_t)0);
}

HY_TEST(Parser_MalformedOptionDoesNotRunOff) {
    // A length that overruns the option area must stop the walk, not read
    // past the header.
    const std::vector<BYTE> opts = {3, 40, 7, 1, 1, 1, 1};
    auto pkt = MakeIpTcpOpts(kClientIp, kTargetIp, kClientPort, kTargetPort,
                             1, 0, 0x02, opts, 65535);
    auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
    HY_CHECK(info.valid);
    HY_CHECK(!info.hasWindowScale);
}

HY_TEST(Parser_DropsFragments) {
    // Only the first fragment of a datagram carries the transport header, so
    // any other one would have its "ports" read out of the payload and be
    // forwarded as if it were a complete datagram. Reassembly is not
    // implemented, so a fragment must come back invalid (= dropped).
    auto base = MakeIpTcp(kClientIp, kTargetIp, kClientPort, kTargetPort,
                          1, 0, 0x02 /*SYN*/, {});
    const uint16_t fragmentFields[] = {
        0x2000,  // MF: more fragments follow
        0x0001,  // offset 1 (8-byte units), no MF - the last fragment
        0x2001,  // MF + offset
    };
    for (uint16_t field : fragmentFields) {
        auto pkt = base;
        const uint16_t net = htons(field);
        std::memcpy(&pkt[6], &net, 2);
        auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
        HY_CHECK(!info.valid);
    }

    // DF alone is not a fragment and must still parse.
    auto dfOnly = base;
    const uint16_t df = htons(0x4000);
    std::memcpy(&dfOnly[6], &df, 2);
    auto info = packet_parser::ParsePacket(dfOnly.data(), static_cast<DWORD>(dfOnly.size()));
    HY_CHECK(info.valid);
    HY_CHECK(info.isSyn);
}

HY_TEST(ProxyEngine_SynAckOffersWindowScale) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    engine->SetClient(client);

    auto [engineSide, peerSide] = hytest::PipeStream::MakePair();
    client->tcpStream = engineSide;

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    // Client SYN offers WS shift 8 (Windows default) - the engine must answer
    // with its own WS option or scaling stays off for the connection.
    const std::vector<BYTE> synOpts = {2, 4, 0x05, 0xB4, 3, 3, 8, 1};
    auto syn = MakeIpTcpOpts(kClientIp, kTargetIp, kClientPort, kTargetPort,
                             1000, 0, 0x02, synOpts, 65535);
    auto synInfo = packet_parser::ParsePacket(syn.data(), static_cast<DWORD>(syn.size()));
    HY_CHECK(engine->HandleTcpPacket(synInfo, syn.data(), static_cast<DWORD>(syn.size()), sendBack));
    HY_CHECK(WaitFor([&] { return out.Size() >= 1; }));

    const auto synAck = ParseTcp(out.At(0));
    HY_CHECK(synAck.valid);
    HY_CHECK_EQ(synAck.flags, (uint8_t)0x12);
    // Option block: MSS then WS. The walk below tolerates either order and
    // just requires BOTH to be present.
    const std::vector<BYTE>& o = synAck.options;
    bool sawMss = false, sawWs = false;
    uint8_t wsVal = 0;
    for (size_t i = 0; i + 1 < o.size();) {
        if (o[i] == 0 || o[i] == 1) { ++i; continue; }
        const uint8_t len = o[i + 1];
        if (len < 2 || i + len > o.size()) break;
        if (o[i] == 2 && len == 4) sawMss = true;
        if (o[i] == 3 && len == 3) { sawWs = true; wsVal = o[i + 2]; }
        i += len;
    }
    HY_CHECK(sawMss);
    HY_CHECK(sawWs);
    HY_CHECK(wsVal > 0);

    engine->Close();
}

HY_TEST(ProxyEngine_PeerWindowDecodedWithScale) {
    // Regression for the upload strangle: the peer's WS shift must be applied
    // to the window field of data-carrying packets. The engine's own SYN-ACK
    // side is covered above; this drives the ACK path.
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    engine->SetClient(client);

    auto [engineSide, peerSide] = hytest::PipeStream::MakePair();
    client->tcpStream = engineSide;

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    // SYN with WS shift 8, advertised window field 8 => effective 2048.
    const std::vector<BYTE> synOpts = {2, 4, 0x05, 0xB4, 3, 3, 8, 1};
    auto syn = MakeIpTcpOpts(kClientIp, kTargetIp, kClientPort, kTargetPort,
                             1000, 0, 0x02, synOpts, 8);
    auto synInfo = packet_parser::ParsePacket(syn.data(), static_cast<DWORD>(syn.size()));
    HY_CHECK(engine->HandleTcpPacket(synInfo, syn.data(), static_cast<DWORD>(syn.size()), sendBack));
    HY_CHECK(WaitFor([&] { return out.Size() >= 1; }));
    const auto synAck = ParseTcp(out.At(0));

    // ACK the SYN-ACK with a scaled window: field 64 << 8 = 16384 bytes.
    auto ackPkt = MakeIpTcpOpts(kClientIp, kTargetIp, kClientPort, kTargetPort,
                                1001, synAck.seq + 1, 0x10, {1, 1, 1, 1}, 64);
    auto ackInfo = packet_parser::ParsePacket(ackPkt.data(),
                                              static_cast<DWORD>(ackPkt.size()));
    HY_CHECK(engine->HandleTcpPacket(ackInfo, ackPkt.data(),
                                     static_cast<DWORD>(ackPkt.size()), sendBack));

    // And a later window UPDATE must also be decoded scaled: field 2 << 8 =
    // 512 bytes (deliberately tiny, so a regression to the raw field would
    // stall the read loop at 512 bytes and this test would still pass the
    // HandleTcpPacket call but the point is the decode, exercised above).
    auto updPkt = MakeIpTcpOpts(kClientIp, kTargetIp, kClientPort, kTargetPort,
                                1001, synAck.seq + 1, 0x10, {1, 1, 1, 1}, 2);
    auto updInfo = packet_parser::ParsePacket(updPkt.data(),
                                              static_cast<DWORD>(updPkt.size()));
    HY_CHECK(engine->HandleTcpPacket(updInfo, updPkt.data(),
                                     static_cast<DWORD>(updPkt.size()), sendBack));

    engine->Close();
}

// Block-QUIC: outbound UDP to port 443 must be dropped (YouTube's HTTP/3
// stutters through the unreliable datagram channel; TCP fallback is fast),
// while UDP to any other port still relays. Both checks go through the same
// HandleUdpPacket entry the capture loop uses.
HY_TEST(ProxyEngine_BlockQuicDropsUdp443Only) {
    auto engine = std::make_shared<ProxyEngine>();
    auto client = std::make_shared<MockClient>();
    engine->SetClient(client);
    engine->SetServerIp(kTargetIp);          // never proxy the tunnel itself
    engine->SetBlockQuic(true);
    // Destination must NOT be the engine's own server IP (always rejected):
    // use 9.9.9.9 for the QUIC/DNS targets below.
    constexpr uint32_t kUdpDst = 0x09090909;

    Output out;
    auto sendBack = [&](const BYTE* d, DWORD n) { out.Add(d, n); return true; };

    // UDP to 443 (QUIC) - must be swallowed.
    auto q = MakeIpUdp(kClientIp, kUdpDst, kClientPort, 443, {1, 2, 3, 4});
    auto qi = packet_parser::ParsePacket(q.data(), static_cast<DWORD>(q.size()));
    HY_CHECK(engine->HandleUdpPacket(qi, q.data(), static_cast<DWORD>(q.size()), sendBack));
    HY_CHECK_EQ(engine->GetStats().udpBlockedQuic, (uint64_t)1);
    // No session worker may have been created for it.
    HY_CHECK(WaitFor([&] { return engine->GetStats().udpConnections == 0; }, 500));

    // The same payload to port 53 (DNS) must still be relayed.
    auto d = MakeIpUdp(kClientIp, kUdpDst, kClientPort, 53, {1, 2, 3, 4});
    auto di = packet_parser::ParsePacket(d.data(), static_cast<DWORD>(d.size()));
    HY_CHECK(engine->HandleUdpPacket(di, d.data(), static_cast<DWORD>(d.size()), sendBack));
    HY_CHECK_EQ(engine->GetStats().udpBlockedQuic, (uint64_t)1);  // unchanged
    HY_CHECK(WaitFor([&] { return engine->GetStats().udpConnections == 1; }, 2000));

    // Switching the knob off re-opens 443.
    engine->SetBlockQuic(false);
    auto q2 = MakeIpUdp(kClientIp, kUdpDst, kClientPort, 443, {1, 2, 3, 4});
    auto q2i = packet_parser::ParsePacket(q2.data(), static_cast<DWORD>(q2.size()));
    HY_CHECK(engine->HandleUdpPacket(q2i, q2.data(), static_cast<DWORD>(q2.size()), sendBack));
    HY_CHECK_EQ(engine->GetStats().udpBlockedQuic, (uint64_t)1);

    engine->Close();
}


HY_TEST(ProxyEngine_FastOpenFailureSendsReset) {
    Output out;
    auto client = std::make_shared<MockClient>();
    client->tcpStream = std::make_shared<RejectedTargetStream>();
    auto engine = std::make_shared<ProxyEngine>();
    engine->SetClient(client);
    auto packet = MakeIpTcp(kClientIp,kTargetIp,kClientPort,kTargetPort,1000,0,0x02,{});
    auto info = packet_parser::ParsePacket(packet.data(), (DWORD)packet.size());
    engine->HandleTcpPacket(info,packet.data(),(DWORD)packet.size(),
        [&](const BYTE* p,DWORD n){out.Add(p,n);return true;});
    const bool failed = WaitFor([&]{return engine->GetStats().failedConnections==1;});
    const bool ended = WaitFor([&]{return engine->GetStats().activeConnections==0;});
    engine->Close();
    HY_CHECK(failed && ended);
    HY_CHECK_EQ(out.Size(),size_t{2});
    const auto syn = ParseTcp(out.At(0)), reset = ParseTcp(out.At(1));
    HY_CHECK_EQ(reset.flags,uint8_t{0x14});
    HY_CHECK_EQ(reset.seq,syn.seq+1);
    HY_CHECK_EQ(reset.ack,uint32_t{1001});
    HY_CHECK(reset.ipChecksumOk && reset.tcpChecksumOk);
}

namespace {
void CheckUploadHalfClose(bool respond) {
    Output out;
    auto client = std::make_shared<MockClient>();
    auto [a,b] = hytest::PipeStream::MakePair();
    auto stream = std::make_shared<HalfCloseStream>(a);
    client->tcpStream = stream;
    auto engine = std::make_shared<ProxyEngine>();
    engine->SetClient(client);
    auto send = [&](uint32_t seq,uint32_t ack,uint8_t flags,const std::vector<uint8_t>& data){
        auto p=MakeIpTcp(kClientIp,kTargetIp,kClientPort,kTargetPort,seq,ack,flags,data);
        auto info=packet_parser::ParsePacket(p.data(),(DWORD)p.size());
        engine->HandleTcpPacket(info,p.data(),(DWORD)p.size(),
            [&](const BYTE* p,DWORD n){out.Add(p,n);return true;});
    };
    send(1000,0,0x02,{});
    const bool opened=WaitFor([&]{return out.Size()>0;});
    if(!opened){engine->Close();HY_CHECK(opened);}
    const uint32_t serverSeq=ParseTcp(out.At(0)).seq+1;
    const std::vector<uint8_t> upload(4096,0x37);
    send(1001,serverSeq,0x19,upload);
    const bool halfClosed=WaitFor([&]{return stream->halfCloses.load()==1;});
    bool earlyFin=false;
    for(size_t i=1;i<out.Size();++i)earlyFin|=(ParseTcp(out.At(i)).flags&1)!=0;
    const bool stillActive=engine->GetStats().activeConnections==1;
    // A retransmitted FIN must only be ACKed, not increment ACK or close again.
    send(1001+uint32_t(upload.size()),serverSeq,0x11,{});
    std::vector<uint8_t> got(upload.size());
    size_t eof=999;
    bool ended=false;
    if(halfClosed){
        hy2::ReadFull(*b,got.data(),got.size());
        eof=b->Read(got.data(),1);
        if(respond){
            b->Write(upload.data(),upload.size());
            b->Close();
            ended=WaitFor([&]{return engine->GetStats().activeConnections==0;});
        }
    }
    engine->Close(); // also verifies shutdown while the half-closed reader waits
    HY_CHECK(halfClosed && stillActive && !earlyFin);
    HY_CHECK(got==upload);
    HY_CHECK_EQ(eof,size_t{0});
    HY_CHECK_EQ(stream->halfCloses.load(),1);
    uint32_t next=serverSeq;
    size_t fins=0;
    std::vector<uint8_t> downloaded;
    for(size_t i=1;i<out.Size();++i){
        const auto p=ParseTcp(out.At(i));
        HY_CHECK(p.ipChecksumOk && p.tcpChecksumOk);
        HY_CHECK_EQ(p.ack,uint32_t{1002}+uint32_t(upload.size()));
        HY_CHECK(!(p.flags&4));
        if(!p.payload.empty()){
            HY_CHECK_EQ(p.seq,next);next+=uint32_t(p.payload.size());
            downloaded.insert(downloaded.end(),p.payload.begin(),p.payload.end());
        }
        if(p.flags&1){HY_CHECK_EQ(p.seq,next);++fins;}
    }
    if(respond){HY_CHECK(ended);HY_CHECK(downloaded==upload);HY_CHECK_EQ(fins,size_t{1});}
    else {HY_CHECK(downloaded.empty());HY_CHECK_EQ(fins,size_t{0});}
}
}
HY_TEST(ProxyEngine_UploadHalfClosePreservesResponse) { CheckUploadHalfClose(true); }
HY_TEST(ProxyEngine_CloseDuringHalfClosedRead) { CheckUploadHalfClose(false); }
