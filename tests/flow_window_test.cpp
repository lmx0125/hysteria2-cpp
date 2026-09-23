// flow_window_test.cpp - Receive-window (flow-control) backpressure tests.
//
// H6 regression: the QUIC receive path used to extend the stream
// flow-control window by at least 1 MB for *every* received chunk,
// independent of how much the application had consumed. A slow reader
// therefore let the peer keep sending without bound and
// Ngtcp2Stream::readBuf_ grew at line rate ("receive window is unbounded").
//
// The fix returns credit on consumption (Ngtcp2Stream::Read ->
// Ngtcp2Connection::ExtendReadCredit), so the peer can never be more than the
// initial receive window (6 MiB with ChromeParrot) ahead of the application.
//
// These tests drive a real ngtcp2 client/server pair over UDP loopback:
//   1. FlowWindow_SlowReaderBoundsSend  - a target that never consumes must
//      stop the client from writing far beyond the bounded window.
//   2. FlowWindow_ConsumingReaderNoStall - a consuming reader must still
//      receive a multi-MB upload (guards against the 6 MiB window stall).

#include "hytest.hpp"
#include "hy2_quic_test_util.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/client.hpp"
#include "hy2/h3/hy_server.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"
#include "hy2/server_iface.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

// IConn used as the proxy target.
//   blockWrites=false: consumes everything instantly (well-behaved reader).
//   blockWrites=true:  Write() blocks until Close(), modelling a target whose
//                      reader stalled, so the server stops reading the QUIC
//                      stream and the receive window/readBuf_ is the only
//                      thing that bounds the client.
class TestTargetConn : public hy2::server::IConn {
public:
    TestTargetConn(bool blockWrites, std::atomic<uint64_t>* bytesConsumed)
        : blockWrites_(blockWrites), bytesConsumed_(bytesConsumed) {}

    size_t Read(uint8_t*, size_t) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return closed_; });
        return 0; // EOF after Close
    }

    void Write(const uint8_t*, size_t n) override {
        if (!blockWrites_) {
            if (bytesConsumed_) bytesConsumed_->fetch_add(n, std::memory_order_relaxed);
            return;
        }
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return closed_; });
    }

    void Close() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            closed_ = true;
        }
        cv_.notify_all();
    }

private:
    bool blockWrites_;
    std::atomic<uint64_t>* bytesConsumed_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool closed_ = false;
};

class TestOutbound : public hy2::server::Outbound {
public:
    explicit TestOutbound(bool blockTargetWrites) : blockWrites_(blockTargetWrites) {}

    std::shared_ptr<hy2::server::IConn> TCP(const std::string&) override {
        auto conn = std::make_shared<TestTargetConn>(blockWrites_, &bytesConsumed_);
        std::lock_guard<std::mutex> lk(mu_);
        targets_.push_back(conn);
        return conn;
    }
    std::shared_ptr<hy2::server::IUdpConn> UDP(const std::string&) override {
        throw hy2::Error("no udp");
    }
    bool CheckUDP(const std::string&) override { return false; }

    // Unblocks every target connection so the server relay threads can finish.
    void CloseTargets() {
        std::vector<std::shared_ptr<TestTargetConn>> snapshot;
        {
            std::lock_guard<std::mutex> lk(mu_);
            snapshot = targets_;
        }
        for (auto& t : snapshot) t->Close();
    }

    uint64_t BytesConsumed() const { return bytesConsumed_.load(std::memory_order_relaxed); }

private:
    bool blockWrites_;
    std::atomic<uint64_t> bytesConsumed_{0};
    std::mutex mu_;
    std::vector<std::shared_ptr<TestTargetConn>> targets_;
};

// Waits until `cond` is true or the timeout elapses. Returns cond().
bool WaitFor(const std::function<bool()>& cond, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (cond()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return cond();
}

struct TestFixture {
    hy2test::TestAuth auth;
    TestOutbound outbound;
    std::unique_ptr<hy2::h3sess::HyServer> server;
    std::shared_ptr<hy2::client::Client> client;
    std::shared_ptr<hy2::IByteReaderWriter> stream;
    std::string serverAddr;

    explicit TestFixture(bool blockTargetWrites, bool udpEnabled = false)
        : outbound(blockTargetWrites) {
        hy2::h3sess::HyServerParams params;
        params.bindAddr = "127.0.0.1";
        params.port = 0; // ephemeral
        params.certPem = hy2test::kTestCertPem;
        params.keyPem = hy2test::kTestKeyPem;
        params.udpEnabled = udpEnabled;
        server = std::make_unique<hy2::h3sess::HyServer>(params, &auth, &outbound);

        serverAddr = "127.0.0.1:" + std::to_string(server->Port());
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

    ~TestFixture() {
        // Order matters: unblock the server relay, tear down the client, then
        // stop the listener so no thread touches freed state.
        if (stream) { try { stream->Close(); } catch (...) {} }
        if (client) { try { client->Close(); } catch (...) {} }
        outbound.CloseTargets();
        if (server) { try { server->Stop(); } catch (...) {} }
    }
};

// Submits `budget` bytes in 256 KB chunks on a worker thread until it either
// reaches the budget or Write() blocks (backpressure/flow control).
struct Writer {
    std::shared_ptr<hy2::IByteReaderWriter> stream;
    std::atomic<uint64_t> submitted{0};
    std::atomic<bool> done{false};
    std::thread thread;

    Writer(std::shared_ptr<hy2::IByteReaderWriter> s, uint64_t budget) : stream(std::move(s)) {
        thread = std::thread([this, budget] {
            std::vector<uint8_t> chunk(256 * 1024, 0x5a);
            while (submitted.load(std::memory_order_relaxed) < budget) {
                try {
                    stream->Write(chunk.data(), chunk.size());
                } catch (...) {
                    break;
                }
                submitted.fetch_add(chunk.size(), std::memory_order_relaxed);
            }
            done.store(true);
        });
    }

    ~Writer() {
        if (thread.joinable()) thread.detach();
    }

    void JoinOrDetach(std::chrono::milliseconds timeout) {
        if (!thread.joinable()) return;
        if (WaitFor([&] { return done.load(); }, timeout)) {
            thread.join();
        } else {
            thread.detach();
        }
    }
};

} // namespace

// ---------------------------------------------------------------------------
// 1. A stalled reader must bound how much the peer can send.
// ---------------------------------------------------------------------------
HY_TEST(FlowWindow_SlowReaderBoundsSend) {
    TestFixture fx(/*blockTargetWrites=*/true);
    HY_CHECK(fx.client != nullptr);
    HY_CHECK(fx.stream != nullptr);

    constexpr uint64_t kChunk = 256 * 1024;
    constexpr uint64_t kMaxSubmit = 32ull * 1024 * 1024;
    // With the bounded window the writer stalls at ~initial window (6 MiB)
    // + write backpressure cap (8 MiB) = ~14 MiB. Without the fix the peer's
    // window grows by >=1 MiB per received chunk and all 32 MiB go through.
    constexpr uint64_t kBound = 20ull * 1024 * 1024;
    (void)kChunk;

    Writer writer(fx.stream, kMaxSubmit);

    // Stop early: either the budget was submitted (unbounded window) or the
    // writer made no progress for 3s (stalled behind the bounded window).
    uint64_t last = 0;
    int idleMs = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < deadline) {
        const uint64_t cur = writer.submitted.load();
        if (cur >= kMaxSubmit) break;
        if (cur == last) {
            idleMs += 100;
            if (idleMs >= 3000) break;
        } else {
            last = cur;
            idleMs = 0;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const uint64_t written = writer.submitted.load();

    fx.stream->Close();   // unblocks a writer parked in the backpressure wait
    fx.client->Close();   // tear the connection down
    writer.JoinOrDetach(std::chrono::seconds(5));
    fx.outbound.CloseTargets();

    std::printf("[flow] stalled writer submitted %llu bytes (bound %llu)\n",
                (unsigned long long)written, (unsigned long long)kBound);
    HY_CHECK(written > 1024 * 1024); // sanity: the pipe actually moved data
    HY_CHECK(written < kBound);      // H6: reader stalls => sender is bounded
}

// ---------------------------------------------------------------------------
// 2. A consuming reader must not stall (guards the 6 MiB window stall).
// ---------------------------------------------------------------------------
HY_TEST(FlowWindow_ConsumingReaderNoStall) {
    TestFixture fx(/*blockTargetWrites=*/false);
    HY_CHECK(fx.client != nullptr);
    HY_CHECK(fx.stream != nullptr);

    constexpr uint64_t kTotal = 16ull * 1024 * 1024;
    Writer writer(fx.stream, kTotal);

    // All 16 MiB must reach the (consuming) target. Before the window-extension
    // work this stalled at the 6 MiB initial stream window; with per-chunk
    // arrival credit it passed; with consumption-driven credit it must still
    // pass without the window ever being starved.
    const bool delivered = WaitFor([&] { return fx.outbound.BytesConsumed() >= kTotal; },
                                   std::chrono::seconds(25));
    const uint64_t consumed = fx.outbound.BytesConsumed();
    writer.JoinOrDetach(std::chrono::seconds(5));
    fx.outbound.CloseTargets();

    std::printf("[flow] consuming reader received %llu bytes\n",
                (unsigned long long)consumed);
    HY_CHECK_EQ(writer.submitted.load(), kTotal);
    HY_CHECK(delivered);
}

#endif // HY2_WITH_QUIC_BACKEND
