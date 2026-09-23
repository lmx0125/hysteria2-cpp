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
