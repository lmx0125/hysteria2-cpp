// rx_drain_test.cpp - The client's QUIC receive drain is bounded per loop turn.
//
// InternalLoop used to drain the socket until recv() reported "would block" in
// one go. With SO_RCVBUF at 32 MB and a 20 MB receive window that can be
// thousands of datagrams, and while the loop runs the connection sends NO ACK
// (they leave through Drive(), which sits outside the loop), samples no
// delivery rate for the peer's BBR, and wakes no reader either -
// FlushReadNotifyBatch is outside the loop as well, so read credit is not
// returned. A whole window of data could then sit unacknowledged for close to a
// full RTT, which is exactly the stall shape seen on real links.
//
// The drain now leaves after kMaxRxDrainPackets, gives Drive() a chance to ACK,
// and comes straight back if the socket still has data (IoWait reports it
// readable). The invariant this test pins is that nothing may be lost or
// stalled by leaving the loop: a multi-megabyte burst driven by the server
// still arrives at the client byte-for-byte, in order, and quickly.
//
// Runs a real ngtcp2 client/server pair over UDP loopback, like the
// flow-window tests.

#include "hytest.hpp"
#include "hy2_quic_test_util.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/client.hpp"
#include "hy2/h3/hy_server.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"
#include "hy2/server_iface.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// IConn handed to the server as the proxy target. Read() produces an endless,
// deterministic byte pattern, so the client can verify every byte it receives
// by absolute offset. Read never returns 0 until the budget is exhausted (a 0
// is an EOF, which makes the server relay stop copying).
class PatternSourceTarget : public hy2::server::IConn {
public:
    std::mutex mu;
    std::condition_variable cv;
    size_t budget = 0;   // total bytes to produce
    size_t produced = 0;
    bool closed = false;

    // Deterministic on the absolute offset, so the receiver can check it.
    static uint8_t ByteAt(size_t offset) {
        return static_cast<uint8_t>((offset * 2654435761u) >> 13);
    }

    size_t Read(uint8_t* p, size_t n) override {
        std::unique_lock<std::mutex> lk(mu);
        cv.wait(lk, [&] { return closed || produced < budget; });
        if (produced >= budget) return 0;  // EOF once the budget is spent
        const size_t give = std::min(n, budget - produced);
        for (size_t i = 0; i < give; i++) {
            p[i] = ByteAt(produced + i);
        }
        produced += give;
        return give;
    }

    void Write(const uint8_t*, size_t n) override {
        consumed.fetch_add(n, std::memory_order_relaxed);
    }

    void Close() override {
        {
            std::lock_guard<std::mutex> lk(mu);
            closed = true;
        }
        cv.notify_all();
    }

    void Configure(size_t bytes) {
        std::lock_guard<std::mutex> lk(mu);
        budget = bytes;
        cv.notify_all();
    }

    std::atomic<uint64_t> consumed{0};
};

class PatternSourceOutbound : public hy2::server::Outbound {
public:
    std::mutex mu;
    std::vector<std::shared_ptr<PatternSourceTarget>> targets;

    std::shared_ptr<hy2::server::IConn> TCP(const std::string&) override {
        auto t = std::make_shared<PatternSourceTarget>();
        std::lock_guard<std::mutex> lk(mu);
        targets.push_back(t);
        return t;
    }
    std::shared_ptr<hy2::server::IUdpConn> UDP(const std::string&) override {
        throw hy2::Error("no udp in this test");
    }
    bool CheckUDP(const std::string&) override { return false; }

    void CloseTargets() {
        std::vector<std::shared_ptr<PatternSourceTarget>> snapshot;
        {
            std::lock_guard<std::mutex> lk(mu);
            snapshot = targets;
        }
        for (auto& t : snapshot) t->Close();
    }
};

struct DrainFixture {
    hy2test::TestAuth auth;
    PatternSourceOutbound outbound;
    std::unique_ptr<hy2::h3sess::HyServer> server;
    std::shared_ptr<hy2::client::Client> client;
    std::shared_ptr<hy2::IByteReaderWriter> stream;
    DrainFixture() {
        hy2::h3sess::HyServerParams params;
        params.bindAddr = "127.0.0.1";
        params.port = 0;  // ephemeral
        params.certPem = hy2test::kTestCertPem;
        params.keyPem = hy2test::kTestKeyPem;
        params.udpEnabled = false;
        server = std::make_unique<hy2::h3sess::HyServer>(params, &auth, &outbound);

        const std::string serverAddr = "127.0.0.1:" + std::to_string(server->Port());
        hy2::quic_backend::RegisterBackend(serverAddr, "localhost", true);

        hy2::client::Config cfg;
        cfg.ServerAddr = serverAddr;
        cfg.Auth = hy2test::TestAuth::kPassword;
        cfg.TLSConfig.ServerName = "localhost";
        cfg.TLSConfig.InsecureSkipVerify = true;
        cfg.VerifyAndFill();

        hy2::client::HandshakeInfo info;
        client = hy2::client::NewClient(cfg, &info);
        if (client) stream = client->TCP("10.0.0.1:80");
    }

    ~DrainFixture() {
        if (stream) { try { stream->Close(); } catch (...) {} }
        if (client) { try { client->Close(); } catch (...) {} }
        outbound.CloseTargets();
        if (server) { try { server->Stop(); } catch (...) {} }
    }
};

// The server-side target appears as soon as the relay dials it.
bool WaitForTargets(PatternSourceOutbound& outbound, int timeoutMs = 5000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lk(outbound.mu);
            if (!outbound.targets.empty()) return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::lock_guard<std::mutex> lk(outbound.mu);
    return !outbound.targets.empty();
}

} // namespace

// ---------------------------------------------------------------------------
// A large burst still arrives complete and in order when the drain is capped.
// The server pushes 16 MB through the relay; the client reads it in 64 KB
// chunks and checks every byte. Anything the drain cap dropped (or left
// unacknowledged long enough to stall the peer) shows up as a short read, a
// hole in the offset chain or a wrong byte.
// ---------------------------------------------------------------------------
HY_TEST(PerfQuic_LargeBurstDeliveredWithBoundedDrain) {
    constexpr size_t kTotal = 16ull * 1024 * 1024;

    DrainFixture fx;
    HY_CHECK(fx.client != nullptr);
    HY_CHECK(fx.stream != nullptr);

    // Start the pattern at the server side before the client reads.
    HY_CHECK(WaitForTargets(fx.outbound));
    {
        std::lock_guard<std::mutex> lk(fx.outbound.mu);
        HY_CHECK(!fx.outbound.targets.empty());
        for (auto& t : fx.outbound.targets) t->Configure(kTotal);
    }

    const auto started = std::chrono::steady_clock::now();
    std::vector<uint8_t> buf(64 * 1024);
    size_t received = 0;
    size_t badBytes = 0;
    const auto deadline = started + std::chrono::seconds(45);
    while (received < kTotal) {
        size_t n = 0;
        try {
            n = fx.stream->Read(buf.data(), buf.size());
        } catch (const std::exception&) {
            break;
        }
        if (n == 0) break;  // EOF
        for (size_t i = 0; i < n; i++) {
            if (buf[i] != PatternSourceTarget::ByteAt(received + i)) badBytes++;
        }
        received += n;
        if (std::chrono::steady_clock::now() > deadline) break;
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;

    std::printf("[perf-h2] received %zu / %zu bytes in %lld ms (%zu bad bytes)\n",
                received, kTotal,
                (long long)std::chrono::duration_cast<std::chrono::milliseconds>(elapsed)
                    .count(),
                badBytes);
    HY_CHECK_EQ(badBytes, (size_t)0);
    HY_CHECK_EQ(received, kTotal);

    fx.outbound.CloseTargets();
}

#endif // HY2_WITH_QUIC_BACKEND
