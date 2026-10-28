// handshake_teardown_test.cpp - a failed handshake must not leave its QUIC
// connection alive.
//
// Why this test exists: Ngtcp2Connection's internal loop thread captures
// shared_from_this(), so the connection is NOT destroyed when the last external
// shared_ptr goes away - it lives until the loop observes closed_. A handshake
// that fails (H3AuthRoundTripper::RoundTrip throwing) used to just drop its
// shared_ptr, leaving the connection - UDP socket and thread included - alive
// until the QUIC idle timeout.
//
// Field shape: the node prober walks unreachable nodes by opening a real
// connection to each, so every failed probe leaked one. Measured 2026-10-11
// with test_node_prober against four unreachable nodes: this process's UDP
// endpoint count climbed 3 -> 30 within 25 s and stayed there. Fixed by closing
// the connection on RoundTrip's failure path (h3_auth.cpp).
//
// The assertion uses the process's own UDP endpoint count: the only observable
// that needs no backend internals. Wake pipes are constant, so only the delta
// across the loop below matters.

#include "hytest.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/client.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#ifndef _WIN32
#error "handshake teardown test is Windows-only (GetExtendedUdpTable)"
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")

namespace {

// UDP endpoints owned by this process (IPv4), or -1 if the table cannot be read.
int CountOwnUdpEndpoints() {
    DWORD size = 0;
    if (GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) !=
        ERROR_INSUFFICIENT_BUFFER) {
        return -1;
    }
    std::vector<uint8_t> buf(size);
    if (GetExtendedUdpTable(buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) !=
        NO_ERROR) {
        return -1;
    }
    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
    const DWORD pid = GetCurrentProcessId();
    int n = 0;
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        if (table->table[i].dwOwningPid == pid) ++n;
    }
    return n;
}

// One connection attempt to a port nothing listens on: the QUIC handshake can
// never complete, so NewClient() throws out of RoundTrip.
void FailHandshakeOnce() {
    hy2::client::Config cfg;
    cfg.ServerAddr = "127.0.0.1:1";
    cfg.Auth = "teardown-test";
    cfg.TLSConfig.ServerName = "localhost";
    cfg.TLSConfig.InsecureSkipVerify = true;
    cfg.QUICConfig.HandshakeTimeout = hy2::Duration::FromSeconds(0.4);
    try {
        hy2::client::NewClient(cfg);
    } catch (const std::exception&) {
        // expected
    }
}

}  // namespace

HY_TEST(StreamLifetime_FailedHandshakeReleasesConnection) {
    // NewClient() runs H3AuthRoundTripper::RoundTrip - the path that has to
    // close the connection when the handshake fails.
    hy2::quic_backend::RegisterBackend("127.0.0.1:1", "localhost", true);

    const int before = CountOwnUdpEndpoints();
    HY_CHECK(before >= 0);

    constexpr int kAttempts = 4;
    for (int i = 0; i < kAttempts; ++i) FailHandshakeOnce();

    // The connection is closed on the failing thread; give the loop a moment to
    // exit and the kernel table to settle.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    const int after = CountOwnUdpEndpoints();
    HY_CHECK(after >= 0);
    // Released connections return the count to where it started. Leaking one
    // socket per attempt would read as +4 here and keep climbing in the field.
    HY_CHECK(after <= before + 1);
}

#endif  // HY2_WITH_QUIC_BACKEND
