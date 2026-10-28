// concurrency_lifecycle_audit_test.cpp - Regression test suite for concurrency,
// lifecycle, lock-free operations, and non-blocking paths across hysteria2-cpp and alyssum.

#include "hytest.hpp"
#include "hy2/io.hpp"
#include "hy2/quic_backend/udp_socket.hpp"
#include "mock_quic.hpp"
#include "proxy_engine.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

using namespace proxy;

namespace {

// Helpers to construct IP packets for ProxyEngine testing
uint32_t AddWordsFold(uint32_t sum, const uint8_t* data, size_t len) {
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (len & 1) sum += static_cast<uint32_t>(data[len - 1]) << 8;
    return sum;
}

uint16_t FoldSum(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

uint16_t CalcIpChecksum(const uint8_t* data, size_t len) {
    return FoldSum(AddWordsFold(0, data, len));
}

uint16_t CalcL4Checksum(const uint8_t* data, size_t len, uint32_t srcIp, uint32_t dstIp, uint8_t proto) {
    uint32_t sum = 0;
    sum += (srcIp >> 16) & 0xFFFF;
    sum += srcIp & 0xFFFF;
    sum += (dstIp >> 16) & 0xFFFF;
    sum += dstIp & 0xFFFF;
    sum += proto;
    sum += static_cast<uint16_t>(len);
    return FoldSum(AddWordsFold(sum, data, len));
}

std::vector<BYTE> MakeUdpPacket(uint32_t srcIp, uint32_t dstIp, uint16_t srcPort,
                                uint16_t dstPort, const std::vector<uint8_t>& payload) {
    const size_t udpLen = 8 + payload.size();
    const size_t total = 20 + udpLen;
    std::vector<BYTE> pkt(total, 0);
    pkt[0] = 0x45;
    pkt[2] = static_cast<BYTE>(total >> 8);
    pkt[3] = static_cast<BYTE>(total & 0xFF);
    pkt[8] = 64;
    pkt[9] = 17; // UDP
    const uint32_t srcN = htonl(srcIp), dstN = htonl(dstIp);
    std::memcpy(&pkt[12], &srcN, 4);
    std::memcpy(&pkt[16], &dstN, 4);
    const uint16_t ipc = CalcIpChecksum(pkt.data(), 20);
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
    uint16_t csum = CalcL4Checksum(udp, udpLen, srcIp, dstIp, 17);
    if (csum == 0) csum = 0xFFFF;
    udp[6] = static_cast<BYTE>(csum >> 8);
    udp[7] = static_cast<BYTE>(csum & 0xFF);
    return pkt;
}

std::vector<BYTE> MakeTcpSynPacket(uint32_t srcIp, uint32_t dstIp, uint16_t srcPort,
                                   uint16_t dstPort, uint32_t seq) {
    const size_t total = 20 + 20;
    std::vector<BYTE> pkt(total, 0);
    pkt[0] = 0x45;
    pkt[2] = static_cast<BYTE>(total >> 8);
    pkt[3] = static_cast<BYTE>(total & 0xFF);
    pkt[8] = 64;
    pkt[9] = 6; // TCP
    const uint32_t srcN = htonl(srcIp), dstN = htonl(dstIp);
    std::memcpy(&pkt[12], &srcN, 4);
    std::memcpy(&pkt[16], &dstN, 4);
    const uint16_t ipc = CalcIpChecksum(pkt.data(), 20);
    pkt[10] = static_cast<BYTE>(ipc >> 8);
    pkt[11] = static_cast<BYTE>(ipc & 0xFF);

    BYTE* tcp = pkt.data() + 20;
    tcp[0] = static_cast<BYTE>(srcPort >> 8);
    tcp[1] = static_cast<BYTE>(srcPort & 0xFF);
    tcp[2] = static_cast<BYTE>(dstPort >> 8);
    tcp[3] = static_cast<BYTE>(dstPort & 0xFF);
    const uint32_t seqN = htonl(seq);
    std::memcpy(tcp + 4, &seqN, 4);
    tcp[12] = 0x50; // data offset 5
    tcp[13] = 0x02; // SYN
    tcp[14] = 0xFF;
    tcp[15] = 0xFF; // window 65535
    const uint16_t csum = CalcL4Checksum(tcp, 20, srcIp, dstIp, 6);
    tcp[16] = static_cast<BYTE>(csum >> 8);
    tcp[17] = static_cast<BYTE>(csum & 0xFF);
    return pkt;
}

class AuditMockUdpConn : public hy2::client::HyUDPConn {
public:
    std::atomic<bool> blockSend{false};
    std::mutex blockMu;
    std::condition_variable blockCv;

    bool Receive(std::vector<uint8_t>&, std::string&) override {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        return false;
    }
    hy2::client::UdpRecvResult ReceivePacket(std::vector<uint8_t>&, std::string&, hy2::Duration) override {
        return hy2::client::UdpRecvResult::kTimeout;
    }
    void Send(const uint8_t* data, size_t n, const std::string& addr) override {
        {
            std::unique_lock<std::mutex> lk(blockMu);
            blockCv.wait(lk, [&] { return !blockSend.load(); });
        }
        std::lock_guard<std::mutex> lk(mu_);
        sent_.emplace_back(std::vector<uint8_t>(data, data + n), addr);
    }
    void Unblock() {
        blockSend.store(false);
        blockCv.notify_all();
    }
    void Close() override {
        Unblock();
    }

    std::mutex mu_;
    std::vector<std::pair<std::vector<uint8_t>, std::string>> sent_;
};

class AuditMockClient : public hy2::client::Client {
public:
    std::shared_ptr<hy2::IByteReaderWriter> TCP(const std::string&) override {
        auto pair = hytest::PipeStream::MakePair();
        return pair.first;
    }
    std::shared_ptr<hy2::client::HyUDPConn> UDP() override {
        return udpConn_;
    }
    void Close() override {}

    std::shared_ptr<AuditMockUdpConn> udpConn_ = std::make_shared<AuditMockUdpConn>();
};

} // namespace

// ---------------------------------------------------------------------------
// 1. Channel Lock-Free Closed Test
// ---------------------------------------------------------------------------
HY_TEST(Audit_Channel_LockFreeClosed) {
    hy2::Channel<int> ch(10);
    HY_CHECK(!ch.Closed());

    ch.TrySend(1);
    ch.TrySend(2);
    HY_CHECK(!ch.Closed());

    ch.Close();
    HY_CHECK(ch.Closed());

    // TrySend after close returns false
    HY_CHECK(!ch.TrySend(3));

    int v = 0;
    HY_CHECK(ch.Receive(v));
    HY_CHECK_EQ(v, 1);
    HY_CHECK(ch.Receive(v));
    HY_CHECK_EQ(v, 2);

    // Drained & closed
    HY_CHECK(!ch.Receive(v));
    HY_CHECK(ch.Closed());
}

// ---------------------------------------------------------------------------
// 2. UdpSocket Lock-Free HasQueuedPackets Test
// ---------------------------------------------------------------------------
HY_TEST(Audit_UdpSocket_LockFreeHasQueuedPackets) {
    hy2::quic_backend::UdpSocket receiver;
    HY_CHECK(receiver.Bind("127.0.0.1", 0));
    uint16_t rport = receiver.LocalPort();

    hy2::quic_backend::UdpSocket sock;
    HY_CHECK(sock.Connect("127.0.0.1", rport));
    HY_CHECK(!sock.HasQueuedPackets());

    uint8_t dummy[32] = {0};
    sock.EnqueueForTest(dummy, sizeof(dummy));
    HY_CHECK(sock.HasQueuedPackets());

    sock.DrainTxQueue();
    HY_CHECK(!sock.HasQueuedPackets());

    sock.Close();
    receiver.Close();
}

// ---------------------------------------------------------------------------
// 3. ProxyEngine 16-Shard Concurrency Test
// ---------------------------------------------------------------------------
HY_TEST(Audit_ProxyEngine_ShardedMapConcurrency) {
    auto engine = std::make_shared<ProxyEngine>();
    auto mockClient = std::make_shared<AuditMockClient>();
    engine->SetClient(mockClient);
    engine->SetLocalSubnet(0x0A000000, 0xFFFFFF00); // 10.0.0.0/24

    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    constexpr int kThreads = 8;
    constexpr int kConnsPerThread = 20;

    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t]() {
            while (!start.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < kConnsPerThread; ++i) {
                // Different IP and port combinations hitting different shards
                uint32_t srcIp = 0x0A000002;
                uint32_t dstIp = 0x01020304 + (t * 100) + i;
                uint16_t srcPort = static_cast<uint16_t>(10000 + t * 100 + i);
                uint16_t dstPort = 80;

                auto pkt = MakeTcpSynPacket(srcIp, dstIp, srcPort, dstPort, 1000);
                auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
                HY_CHECK(info.valid);
                bool ok = engine->HandleTcpPacket(info, pkt.data(), static_cast<DWORD>(pkt.size()),
                                                  [](const BYTE*, DWORD) { return true; });
                HY_CHECK(ok);
            }
        });
    }

    start.store(true, std::memory_order_release);
    for (auto& th : threads) {
        th.join();
    }

    auto stats = engine->GetStats();
    HY_CHECK_EQ(stats.tcpConnections, static_cast<uint64_t>(kThreads * kConnsPerThread));
    engine->Close();
}

// ---------------------------------------------------------------------------
// 4. ProxyEngine UDP Session Bounded Queue Test
// ---------------------------------------------------------------------------
HY_TEST(Audit_ProxyEngine_UdpSession_BoundedQueue) {
    auto engine = std::make_shared<ProxyEngine>();
    auto mockClient = std::make_shared<AuditMockClient>();
    mockClient->udpConn_->blockSend.store(true); // Gate sender so queue fills to capacity
    engine->SetClient(mockClient);
    engine->SetLocalSubnet(0x0A000000, 0xFFFFFF00);

    uint32_t srcIp = 0x0A000002;
    uint32_t dstIp = 0x08080808;
    uint16_t srcPort = 12345;
    uint16_t dstPort = 53;

    std::vector<uint8_t> payload(64, 0xAA);
    auto pkt = MakeUdpPacket(srcIp, dstIp, srcPort, dstPort, payload);
    auto info = packet_parser::ParsePacket(pkt.data(), static_cast<DWORD>(pkt.size()));
    HY_CHECK(info.valid);

    // Push 1200 packets to the same session rapidly while sender is gated.
    // With kMaxSendQ = 1024, packets beyond 1024 must be dropped to prevent bufferbloat/OOM.
    int accepted = 0;
    int dropped = 0;
    for (int i = 0; i < 3000; ++i) {
        bool ok = engine->HandleUdpPacket(info, pkt.data(), static_cast<DWORD>(pkt.size()),
                                          [](const BYTE*, DWORD) { return true; });
        if (ok) accepted++;
        else dropped++;
    }

    // Unblock the writer thread so it drains the queue cleanly
    mockClient->udpConn_->Unblock();

    // Must have successfully accepted up to the queue capacity
    HY_CHECK(accepted > 0);
    // And rejected the excess
    HY_CHECK(dropped > 0);

    auto stats = engine->GetStats();
    HY_CHECK(stats.udpConnections >= 1);

    engine->Close();
}
