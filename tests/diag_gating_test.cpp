// diag_gating_test.cpp - H1 regression: hot-path diagnostics must be gated.
//
// SendDatagram used to update its diagnostic counters and read
// steady_clock::now() unconditionally, so every relayed UDP datagram paid
// ~4 atomic RMWs and 4-6 clock reads even with diagnostics off (SendPacket
// already gated its counters correctly).
//
// The test completes a real QUIC handshake + auth round trip against a local
// server and asserts that the datagram counters stay zero by default. With
// the bug they were incremented on every SendDatagram, so this fails before
// the fix and passes after it.

#include "hytest.hpp"
#include "hy2_quic_test_util.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/client.hpp"
#include "hy2/h3/hy_server.hpp"
#include "hy2/quic_backend/h3_auth.hpp"
#include "hy2/quic_backend/ngtcp2_connection.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

class ThrowingOutbound : public hy2::server::Outbound {
public:
    std::shared_ptr<hy2::server::IConn> TCP(const std::string&) override {
        throw hy2::Error("no tcp");
    }
    std::shared_ptr<hy2::server::IUdpConn> UDP(const std::string&) override {
        throw hy2::Error("no udp");
    }
    bool CheckUDP(const std::string&) override { return false; }
};

} // namespace

HY_TEST(DiagGating_SendDatagramCountersQuietByDefault) {
    // If diagnostics were explicitly enabled (environment), the premise of
    // the test changes - skip rather than report a false failure.
    if (std::getenv("HY2_BW_DIAG") || std::getenv("HY2_DIAG")) {
        std::printf("[diag] HY2_BW_DIAG/HY2_DIAG set: skipping gating assertion\n");
        return;
    }

    hy2test::TestAuth auth;
    ThrowingOutbound outbound;
    hy2::h3sess::HyServerParams params;
    params.bindAddr = "127.0.0.1";
    params.port = 0;
    params.certPem = hy2test::kTestCertPem;
    params.keyPem = hy2test::kTestKeyPem;
    params.udpEnabled = false; // datagram TX/RX is transport level, no relay needed
    hy2::h3sess::HyServer server(params, &auth, &outbound);

    const std::string addr = "127.0.0.1:" + std::to_string(server.Port());

    hy2::client::Config cfg;
    cfg.ServerAddr = addr;
    cfg.Auth = hy2test::TestAuth::kPassword;
    cfg.TLSConfig.ServerName = "localhost";
    cfg.TLSConfig.InsecureSkipVerify = true;
    cfg.VerifyAndFill();

    hy2::quic_backend::H3AuthRoundTripper::Params tp;
    tp.serverAddr = addr;
    tp.serverName = "localhost";
    tp.insecureSkipVerify = true;
    hy2::quic_backend::H3AuthRoundTripper transport(tp);

    hy2::proto::AuthRequest req;
    req.Auth = cfg.Auth;
    req.Rx = 0;
    auto result = transport.RoundTrip(cfg, req);
    HY_CHECK(result.Conn != nullptr);

    auto conn = std::dynamic_pointer_cast<hy2::quic_backend::Ngtcp2Connection>(result.Conn);
    HY_CHECK(conn != nullptr);

    // Exercise the real datagram TX path (handshake + auth completed above,
    // so the peer's max_datagram_frame_size is known).
    std::vector<uint8_t> payload(64, 0x42);
    conn->SendDatagram(payload.data(), payload.size());
    conn->SendDatagram(payload.data(), payload.size());

    const auto& d = conn->DiagCounters();
    HY_CHECK_EQ(d.dgramTxCalls.load(std::memory_order_relaxed), (uint64_t)0);
    HY_CHECK_EQ(d.dgramTxSuccess.load(std::memory_order_relaxed), (uint64_t)0);
    HY_CHECK_EQ(d.dgramTxLockWaitNs.load(std::memory_order_relaxed), (uint64_t)0);
    HY_CHECK_EQ(d.dgramTxLockHoldNs.load(std::memory_order_relaxed), (uint64_t)0);

    conn->CloseWithError(0, "");
    server.Stop();
}

#endif // HY2_WITH_QUIC_BACKEND
