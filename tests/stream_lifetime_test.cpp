// stream_lifetime_test.cpp - regression tests for the transport lifetime audit
// (AUDIT_REPORT.md H1/H2).
//
// H1: an application can hold a stream after the connection it belongs to is
//     destroyed. The client pool drops its Client on a node switch while the
//     proxied flow keeps its stream, and the connection itself is then only
//     kept alive by its own IO thread - which exits (and frees everything) as
//     soon as the peer closes or the idle timeout fires. Read()/Write() on that
//     stream must observe the close: the old raw `Ngtcp2Connection*` was
//     dereferenced (WakeUpOnData / ExtendReadCredit) and Read() parked forever
//     in the 100 ms re-check loop.
//
// H2: AcceptStream()/AcceptUniStream() must be released when the connection
//     closes. They park on `closed_` but only a *new* stream used to notify the
//     condition variable, so the server's accept loops (server.cpp
//     handleClient) never woke up and Server::Close() hung in join().
//
// Both tests run against a real ngtcp2 pair (bare listener, no H3/auth), like
// tests/udp_datagram_test.cpp.

#include "hytest.hpp"
#include "hy2_quic_test_util.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/quic_backend/ngtcp2_listener.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

// Listener + client connection + accepted server connection over UDP loopback.
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

        hy2::QuicConfig qc;
        client = hy2::quic_backend::CreateQuicConnection(addr, "localhost", qc, true);

        // Accept() returns only after the server saw the handshake complete.
        server = listener->Accept();
        if (!server) throw std::runtime_error("accept failed");
    }

    ~RawQuicPair() {
        try { if (client) client->CloseWithError(0, ""); } catch (...) {}
        try { if (server) server->CloseWithError(0, ""); } catch (...) {}
        try { if (listener) listener->Close(); } catch (...) {}
    }

    // Declaration order matters: server-side connections keep non-owning
    // pointers into the listener (socket, wake pipe), so it must die last.
    std::shared_ptr<hy2::quic_backend::Ngtcp2Listener> listener;
    std::shared_ptr<hy2::IQuicConnection> client;
    std::shared_ptr<hy2::IQuicConnection> server;
    std::string addr;
};

bool WaitFor(const std::function<bool()>& cond, int timeoutMs) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (!cond() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return cond();
}

} // namespace

// ---------------------------------------------------------------------------
// H1: a stream the application kept must survive its connection's death.
// ---------------------------------------------------------------------------
HY_TEST(StreamLifetime_ReadWriteAfterConnectionDeath)
{
    RawQuicPair pair;

    std::shared_ptr<hy2::IQuicStream> stream = pair.client->OpenStream();
    HY_CHECK(stream != nullptr);

    // The stream works while the connection is alive.
    const uint8_t payload[4] = {1, 2, 3, 4};
    stream->Write(payload, sizeof(payload));

    std::weak_ptr<hy2::IQuicConnection> weakConn = pair.client;
    pair.client->CloseWithError(0x100, "");
    // Drop the last external reference: from here on the connection is owned
    // only by its own IO thread, exactly like a client the pool has replaced.
    pair.client.reset();

    // It must go away on its own once the IO loop observes closed_.
    HY_CHECK(WaitFor([&] { return weakConn.expired(); }, 5000));

    // Read() on the detached stream must report EOF instead of parking in the
    // 100 ms re-check loop forever.
    std::atomic<bool> readDone{false};
    std::thread reader([&] {
        uint8_t buf[64];
        size_t n = 0;
        try {
            n = stream->Read(buf, sizeof(buf));
        } catch (...) {
            n = 0;
        }
        (void)n;
        readDone.store(true);
    });
    const bool readReturned = WaitFor([&] { return readDone.load(); }, 3000);
    if (!readReturned) {
        reader.detach(); // never leave a blocked thread behind a failure
    } else {
        reader.join();
    }
    HY_CHECK(readReturned);

    // Write() must fail cleanly instead of notifying the freed connection.
    bool threw = false;
    try {
        stream->Write(payload, sizeof(payload));
    } catch (...) {
        threw = true;
    }
    HY_CHECK(threw);
}

// ---------------------------------------------------------------------------
// H2: closing a connection must release its accept waiters.
// ---------------------------------------------------------------------------
HY_TEST(StreamLifetime_AcceptWaiterReleasedOnClose)
{
    RawQuicPair pair;

    std::atomic<bool> done{false};
    std::atomic<bool> gotClosedError{false};
    std::thread waiter([&] {
        try {
            pair.client->AcceptStream(); // no incoming streams: parks
        } catch (...) {
            gotClosedError.store(true);
        }
        done.store(true);
    });

    // Let the waiter park inside the condition variable.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    pair.client->CloseWithError(0, "");

    const bool released = WaitFor([&] { return done.load(); }, 3000);
    if (!released) {
        waiter.detach();
    } else {
        waiter.join();
    }
    HY_CHECK(released);
    HY_CHECK(gotClosedError.load());
}

// ---------------------------------------------------------------------------
// Peer-initiated close must release the SERVER-side waiters.
//
// The H2 test above closes the LOCAL connection (CloseWithError), and that path
// always called WakeAllWaiters(). The other way a connection dies is the peer's
// CONNECTION_CLOSE arriving in the IO loop: read_pkt returns DRAINING (or
// handle_expiry fails on the idle timeout), which set closed_ WITHOUT waking
// anyone - and unlike InternalLoop(), ServerLoop() did not wake the waiters
// when it exited either.
//
// These tests park a waiter on the *server* connection and close from the
// client, which is the direction that leaked: every waiter stayed parked for
// the rest of the process lifetime, and since HySession::Serve() joins the
// accept and datagram loops, the whole session worker and its detached
// children were never torn down. Measured on the local server: ~9 threads and
// ~9MB per closed connection, never reclaimed even after minutes of idle.
HY_TEST(StreamLifetime_AcceptWaiterReleasedOnPeerClose)
{
    RawQuicPair pair;

    std::atomic<bool> done{false};
    std::atomic<bool> gotClosedError{false};
    std::thread waiter([&] {
        try {
            pair.server->AcceptStream(); // no incoming streams: parks
        } catch (...) {
            gotClosedError.store(true);
        }
        done.store(true);
    });

    // Let the waiter park inside the condition variable.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Peer-initiated: the client sends CONNECTION_CLOSE and the server's
    // ServerLoop reads it, entering the draining state inside read_pkt.
    pair.client->CloseWithError(0, "");

    const bool released = WaitFor([&] { return done.load(); }, 5000);
    if (!released) {
        waiter.detach();
    } else {
        waiter.join();
    }
    HY_CHECK(released);
    HY_CHECK(gotClosedError.load());
}

// The same guarantee for the unidirectional accept loop (the server drains the
// peer's control/QPACK uni streams there).
HY_TEST(StreamLifetime_UniAcceptWaiterReleasedOnPeerClose)
{
    RawQuicPair pair;

    std::atomic<bool> done{false};
    std::thread waiter([&] {
        try {
            pair.server->AcceptUniStream();
        } catch (...) {
        }
        done.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    pair.client->CloseWithError(0, "");

    const bool released = WaitFor([&] { return done.load(); }, 5000);
    if (!released) {
        waiter.detach();
    } else {
        waiter.join();
    }
    HY_CHECK(released);
}

// And for the datagram consumer, which parks on its own queue.
HY_TEST(StreamLifetime_DatagramWaiterReleasedOnPeerClose)
{
    RawQuicPair pair;

    std::atomic<bool> done{false};
    std::thread waiter([&] {
        try {
            pair.server->ReceiveDatagram();
        } catch (...) {
        }
        done.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    pair.client->CloseWithError(0, "");

    const bool released = WaitFor([&] { return done.load(); }, 5000);
    if (!released) {
        waiter.detach();
    } else {
        waiter.join();
    }
    HY_CHECK(released);
}

#endif // HY2_WITH_QUIC_BACKEND
