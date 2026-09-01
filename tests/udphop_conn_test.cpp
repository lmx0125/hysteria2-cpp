// udphop_conn_test.cpp - Tests for UDP port hopping connection.
#include "hytest.hpp"
#include "hy2/udphop/udphop_conn.hpp"
#include "hy2/udphop/udphop.hpp"

#include <thread>
#include <chrono>
#include <atomic>
#include <cstring>

using namespace hy2::udphop;

HY_TEST(UDPHopConn_CreateAndClose) {
    UDPHopAddr addr;
    addr.IP = "127.0.0.1";
    addr.Ports = {10001};
    addr.PortStr = "10001";

    HopIntervalConfig hop;
    hop.minNs = 30000000000LL;
    hop.maxNs = 30000000000LL;

    auto* conn = CreateUdpHopConn(addr, hop);
    HY_CHECK(conn != nullptr);
    HY_CHECK(!conn->IsClosed());

    // LocalAddr should return something
    std::string local = conn->LocalAddr();
    HY_CHECK(!local.empty());

    conn->Close();
    HY_CHECK(conn->IsClosed());
    delete conn;
}

HY_TEST(UDPHopConn_LocalAddrFormat) {
    UDPHopAddr addr;
    addr.IP = "127.0.0.1";
    addr.Ports = {20001, 20002};
    addr.PortStr = "20001,20002";

    HopIntervalConfig hop;
    hop.minNs = 60000000000LL;
    hop.maxNs = 60000000000LL;

    auto* conn = CreateUdpHopConn(addr, hop);
    HY_CHECK(conn != nullptr);

    std::string local = conn->LocalAddr();
    HY_CHECK(!local.empty());
    // Local address should contain a colon (host:port format)
    HY_CHECK(local.find(':') != std::string::npos);

    conn->Close();
    delete conn;
}

HY_TEST(UDPHopConn_CloseIdempotent) {
    UDPHopAddr addr;
    addr.IP = "127.0.0.1";
    addr.Ports = {30001};
    addr.PortStr = "30001";

    HopIntervalConfig hop;
    hop.minNs = 30000000000LL;
    hop.maxNs = 30000000000LL;

    auto* conn = CreateUdpHopConn(addr, hop);
    HY_CHECK(conn != nullptr);

    conn->Close();
    conn->Close(); // second close should be no-op
    HY_CHECK(conn->IsClosed());
    delete conn;
}
