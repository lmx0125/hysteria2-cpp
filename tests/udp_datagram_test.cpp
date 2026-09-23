// udp_datagram_test.cpp - H2 regression tests for the QUIC datagram receive
// channel.
//
// The receive queue used to be a std::vector with erase(begin()) per pop,
// shared mu_ with stream callbacks, a notify per datagram, and no wake on
// connection close. These tests drive two real ngtcp2 connections through a
// bare listener (no H3 auth / session layer) so only the transport datagram
// path is involved:
//   1. UdpDatagram_CloseUnblocksReceive - a consumer parked in
//      ReceiveDatagram() must be unblocked by CloseWithError() (before the
//      fix it parked forever).
//   2. UdpDatagram_BurstKeepsOrder - a burst of datagrams must be delivered
//      through the receive queue in FIFO order.

#include "hytest.hpp"
#include "hy2_quic_test_util.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/protocol.hpp"
#include "hy2/quic_backend/ngtcp2_listener.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace {

// Two connected QUIC endpoints (client + accepted server connection) over
// UDP loopback. No H3/auth/session layer: the transport datagram path only.
class RawQuicPair {
public:
    RawQuicPair() {
        hy2::quic_backend::Ngtcp2Listener::ServerParams sp;
        sp.bindAddr = "127.0.0.1";
        sp.port = 0; // ephemeral
        sp.certChainPEM = {hy2test::kTestCertPem};
        sp.privateKeyPEM = {hy2test::kTestKeyPem};
        sp.datagramEnabled = true;
        listener = hy2::quic_backend::Ngtcp2Listener::Create(sp);
        if (!listener) throw std::runtime_error("listener create failed");

        addr = "127.0.0.1:" + std::to_string(listener->GetSocketRaw()->LocalPort());

        hy2::QuicConfig qc; // datagrams enabled client-side by default
        client = hy2::quic_backend::CreateQuicConnection(addr, "localhost", qc, true);

        // Accept() only returns once the server saw the handshake complete,
        // so both endpoints are ready afterwards.
        server = listener->Accept();
        if (!server) throw std::runtime_error("accept failed");
    }

    ~RawQuicPair() {
        try { if (client) client->CloseWithError(0, ""); } catch (...) {}
        try { if (server) server->CloseWithError(0, ""); } catch (...) {}
        try { if (listener) listener->Close(); } catch (...) {}
    }

    // Declaration order matters: the server-side connection keeps a
    // non-owning wake-pipe pointer / socket pointer into the listener, so the
    // listener must be destroyed LAST (reverse declaration order).
    std::shared_ptr<hy2::quic_backend::Ngtcp2Listener> listener;
    std::shared_ptr<hy2::IQuicConnection> client;
    std::shared_ptr<hy2::IQuicConnection> server;
    std::string addr;
};

std::vector<uint8_t> MakeFrame(uint32_t seq) {
    hy2::proto::UDPMessage m;
    m.SessionID = 7;
    m.PacketID = 0;
    m.FragID = 0;
    m.FragCount = 1;
    m.Addr = "10.0.0.1:53";
    m.Data = {static_cast<uint8_t>(seq >> 24), static_cast<uint8_t>(seq >> 16),
              static_cast<uint8_t>(seq >> 8), static_cast<uint8_t>(seq)};
    std::vector<uint8_t> frame(m.Size());
    const int n = m.Serialize(frame.data(), frame.size());
    if (n <= 0) throw std::runtime_error("serialize failed");
    frame.resize(static_cast<size_t>(n));
    return frame;
}

} // namespace

// ---------------------------------------------------------------------------
// 1. Close must unblock a parked datagram consumer.
// ---------------------------------------------------------------------------
HY_TEST(UdpDatagram_CloseUnblocksReceive) {
    RawQuicPair pair;

    std::atomic<bool> unblocked{false};
    std::thread consumer([&] {
        try {
            pair.client->ReceiveDatagram(); // no datagrams yet: parks
        } catch (...) {
        }
        unblocked.store(true);
    });

    // Give the consumer time to park inside the condition variable.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    pair.client->CloseWithError(0, "");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!unblocked.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    const bool ok = unblocked.load();
    if (!ok) {
        consumer.detach(); // never leave a blocked thread behind a failure
    } else {
        consumer.join();
    }
    HY_CHECK(ok);
}

// ---------------------------------------------------------------------------
// 2. A datagram burst is delivered in FIFO order.
// ---------------------------------------------------------------------------
HY_TEST(UdpDatagram_BurstKeepsOrder) {
    RawQuicPair pair;

    constexpr int kCount = 50;
    for (int i = 0; i < kCount; i++) {
        const auto frame = MakeFrame(static_cast<uint32_t>(i));
        pair.server->SendDatagram(frame.data(), frame.size());
    }

    std::vector<uint32_t> seqs;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (static_cast<int>(seqs.size()) < kCount &&
           std::chrono::steady_clock::now() < deadline) {
        std::vector<uint8_t> d;
        try {
            d = pair.client->ReceiveDatagram();
        } catch (...) {
            break;
        }
        try {
            auto m = hy2::proto::ParseUDPMessage(d.data(), d.size());
            if (m.Data.size() == 4) {
                seqs.push_back((static_cast<uint32_t>(m.Data[0]) << 24) |
                               (static_cast<uint32_t>(m.Data[1]) << 16) |
                               (static_cast<uint32_t>(m.Data[2]) << 8) |
                               static_cast<uint32_t>(m.Data[3]));
            }
        } catch (...) {
            // malformed frame: ignore
        }
    }

    std::printf("[h2] burst: %zu/%d datagrams received\n", seqs.size(), kCount);
    // QUIC DATAGRAM is unreliable by contract, but on loopback a 50-packet
    // burst should arrive (small margin for scheduler races).
    HY_CHECK(seqs.size() >= (size_t)(kCount * 9 / 10));
    for (size_t i = 1; i < seqs.size(); i++) {
        HY_CHECK(seqs[i] > seqs[i - 1]); // FIFO order preserved
    }
}

#endif // HY2_WITH_QUIC_BACKEND
