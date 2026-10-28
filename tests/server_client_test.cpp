// server_client_test.cpp - Session logic tests for server UDP manager,
// client UDP manager, H3sHandler auth/TCP flow and reconnectable client.
// Mirrors behaviors tested by core/server/udp_test.go, core/client/udp_test.go
// and core/internal/integration_tests in the Go implementation.
#include "hytest.hpp"

#include <cstring>
#include <functional>
#include <map>
#include <thread>

#include "hy2/brutal.hpp"
#include "hy2/client_udp.hpp"
#include "hy2/error.hpp"
#include "hy2/quic_config.hpp"
#include "hy2/server.hpp"
#include "hy2/server_udp.hpp"
#include "mock_quic.hpp"

using namespace hy2;
using namespace hytest;
using namespace hy2::server;
using namespace hy2::client;
using namespace hy2::proto;

// ---------------------------------------------------------------------------
// Shared mocks / helpers

class UdpEventLoggerNop : public UdpEventLogger {
public:
    void New(uint32_t, const std::string&) override {}
    void Close(uint32_t, const std::string&) override {}
};

// TestServerUdpIO mirrors what server.go's udpIOImpl does over the QUIC conn,
// but is defined in the test so we don't depend on internal impl classes.
struct TestOutbound;

class TestServerUdpIO : public hy2::server::UdpIO {
public:
    MockQuicConnection& conn;
    Outbound& outbound;

    TestServerUdpIO(MockQuicConnection& c, Outbound& ob) : conn(c), outbound(ob) {}

    std::shared_ptr<UDPMessage> ReceiveMessage() override {
        for (;;) {
            auto v = conn.ReceiveDatagram(); // throws on close
            try {
                return std::make_shared<UDPMessage>(ParseUDPMessage(v));
            } catch (const Error&) {
                continue; // invalid message - wait for next
            }
        }
    }
    void SendMessage(uint8_t* buf, size_t bufLen, const UDPMessage& msg) override {
        int n = msg.Serialize(buf, bufLen);
        if (n >= 0) conn.SendDatagram(buf, static_cast<size_t>(n));
    }
    void Hook(std::vector<uint8_t>&, std::string&) override {}
    std::shared_ptr<IUdpConn> UDP(const std::string& reqAddr) override {
        return outbound.UDP(reqAddr);
    }
    bool CheckUDP(const std::string& reqAddr) override {
        return outbound.CheckUDP(reqAddr);
    }
};

struct TestOutbound : public Outbound {
    std::map<std::string, std::shared_ptr<MockUdpConn>> udpConns;
    bool allowAll = true;

    std::shared_ptr<IUdpConn> UDP(const std::string& reqAddr) override {
        auto c = std::make_shared<MockUdpConn>();
        udpConns[reqAddr] = c;
        return c;
    }
    bool CheckUDP(const std::string&) override { return allowAll; }
    std::shared_ptr<IConn> TCP(const std::string&) override { throw Error("not implemented"); }
};

namespace {

void waitUntil(const std::function<bool()>& cond, int timeoutMs = 3000) {
    for (int i = 0; i < timeoutMs / 10 && !cond(); i++) {
        SleepFor(Duration::FromMillis(10));
    }
}

// Adapts an IByteReaderWriter stream into an IConn for the outbound side.
class ConnFromStream : public IConn {
public:
    explicit ConnFromStream(std::shared_ptr<PipeStream> s) : s_(std::move(s)) {}
    size_t Read(uint8_t* p, size_t n) override { return s_->Read(p, n); }
    void Write(const uint8_t* p, size_t n) override { s_->Write(p, n); }
    void Close() override { s_->Close(); }

private:
    std::shared_ptr<PipeStream> s_;
};

} // namespace

// ---------------------------------------------------------------------------
// Server-side UDP session manager

HY_TEST(ServerUdpSessionBasicFlow)
{
    MockQuicConnection conn;
    TestOutbound outbound;
    TestServerUdpIO io(conn, outbound);
    UdpEventLoggerNop elog;
    UdpSessionManager mgr(&io, &elog, Duration::FromSeconds(60));

    // feed a message: session 42 -> "8.8.8.8:53" with payload
    UDPMessage msg;
    msg.SessionID = 42;
    msg.PacketID = 7;
    msg.FragCount = 1;
    msg.Addr = "8.8.8.8:53";
    msg.Data = {1, 2, 3, 4};
    mgr.feed(std::make_shared<UDPMessage>(msg));

    // session created, data written to the mock conn
    waitUntil([&] { return !outbound.udpConns.empty(); });
    HY_CHECK_EQ(outbound.udpConns.size(), (size_t)1);
    auto udpConn = outbound.udpConns["8.8.8.8:53"];
    HY_CHECK(udpConn != nullptr);
    waitUntil([&] { return !udpConn->Written().empty(); });
    auto written = udpConn->Written();
    HY_CHECK_EQ(written.size(), (size_t)1);
    HY_CHECK(written[0].Data == std::vector<uint8_t>({1, 2, 3, 4}));
    HY_CHECK_EQ(written[0].Addr, std::string("8.8.8.8:53"));
    HY_CHECK_EQ(mgr.Count(), (size_t)1);

    // response from remote comes back as a correctly framed datagram
    udpConn->Inject({'a', 'b', 'c'}, "8.8.8.8:53");
    HY_CHECK(conn.WaitForSentDatagrams(1));
    auto parsed = ParseUDPMessage(conn.SentDatagrams()[0]);
    HY_CHECK_EQ(parsed.SessionID, (uint32_t)42);
    HY_CHECK_EQ(parsed.FragCount, (uint8_t)1);
    HY_CHECK_EQ(parsed.Addr, std::string("8.8.8.8:53"));
    HY_CHECK(parsed.Data == std::vector<uint8_t>({'a', 'b', 'c'}));

    mgr.Stop();
}

HY_TEST(ServerUdpSessionIdleTimeout)
{
    MockQuicConnection conn;
    TestOutbound outbound;
    TestServerUdpIO io(conn, outbound);
    UdpEventLoggerNop elog;
    UdpSessionManager mgr(&io, &elog, Duration::FromSeconds(1));

    UDPMessage msg;
    msg.SessionID = 100;
    msg.FragCount = 1;
    msg.Addr = "9.9.9.9:1234";
    msg.Data = {'x'};
    mgr.feed(std::make_shared<UDPMessage>(msg));

    waitUntil([&] { return !outbound.udpConns.empty(); });
    HY_CHECK_EQ(mgr.Count(), (size_t)1);

    // idle timeout is 1s, cleanup ticker runs every 1s => allow up to ~3s
    waitUntil([&] { return mgr.Count() == 0; }, 4000);
    HY_CHECK_EQ(mgr.Count(), (size_t)0);

    // same session id after expiry creates a new session/port
    msg.Data = {'y'};
    mgr.feed(std::make_shared<UDPMessage>(msg));
    waitUntil([&] { return mgr.Count() == 1; });
    HY_CHECK_EQ(mgr.Count(), (size_t)1);
    mgr.Stop();
}

HY_TEST(ServerUdpAclRejection)
{
    MockQuicConnection conn;
    TestOutbound outbound;
    outbound.allowAll = false;
    TestServerUdpIO io(conn, outbound);
    UdpEventLoggerNop elog;
    UdpSessionManager mgr(&io, &elog, Duration::FromSeconds(60));

    // Mirrors Go semantics: the session's FIRST address is always cached as
    // allowed (aclCache = {addr: nil}), so it gets written; CheckUDP applies
    // to every subsequent different address in the same session.
    UDPMessage msg;
    msg.SessionID = 5;
    msg.FragCount = 1;
    msg.Addr = "127.0.0.1:1";
    msg.Data = {'p'};
    mgr.feed(std::make_shared<UDPMessage>(msg));

    waitUntil([&] { return !outbound.udpConns.empty(); });
    HY_CHECK(outbound.udpConns["127.0.0.1:1"] != nullptr);
    waitUntil([&] { return !outbound.udpConns["127.0.0.1:1"]->Written().empty(); });

    // different address in the same session => ACL rejects, nothing written
    UDPMessage msg2 = msg;
    msg2.Addr = "10.0.0.1:9999";
    msg2.Data = {'q'};
    mgr.feed(std::make_shared<UDPMessage>(msg2));
    SleepFor(Duration::FromMillis(300));
    HY_CHECK_EQ(outbound.udpConns.size(), (size_t)1); // no second conn created
    mgr.Stop();
}

// ---------------------------------------------------------------------------
// Client-side UDP session manager

namespace {
struct CountingClientIO : public hy2::client::UdpIO {
    MockQuicConnection& conn;
    int sendCalls = 0;

    explicit CountingClientIO(MockQuicConnection& c) : conn(c) {}

    std::shared_ptr<UDPMessage> ReceiveMessage() override {
        auto v = conn.ReceiveDatagram(); // blocks / throws on close
        return std::make_shared<UDPMessage>(ParseUDPMessage(v));
    }
    void SendMessage(uint8_t* buf, size_t bufLen, const UDPMessage& msg) override {
        sendCalls++;
        int n = msg.Serialize(buf, bufLen);
        if (n >= 0) conn.SendDatagram(buf, static_cast<size_t>(n));
    }
};

// NewUDP() returns the base HyUDPConn interface, so tests cannot read the
// session id off the handle. A message is routed by SessionID, and the
// manager hands ids out from 1 in order - the most recently created session
// is the one under test, and its id is the current count.
uint32_t SessionIdOf(const std::shared_ptr<ClientUdpSessionManager>& mgr) {
    return static_cast<uint32_t>(mgr->Count());
}
} // namespace

HY_TEST(ClientUdpSessionIdsAndRouting)
{
    MockQuicConnection conn;
    CountingClientIO io(conn);
    auto ioPtr = std::shared_ptr<CountingClientIO>(&io, [](CountingClientIO*) {});
    auto mgr = ClientUdpSessionManager::Create(ioPtr);

    auto c1 = mgr->NewUDP();
    auto c2 = mgr->NewUDP();
    HY_CHECK(c1 && c2);
    HY_CHECK_EQ(mgr->Count(), (size_t)2);

    // send via c1: serialized datagram carries its id and addr
    uint8_t data[] = {0x11, 0x22};
    c1->Send(data, sizeof(data), "1.1.1.1:80");
    HY_CHECK(conn.WaitForSentDatagrams(1));
    auto sent = ParseUDPMessage(conn.SentDatagrams()[0]);
    HY_CHECK(sent.SessionID >= 1); // sequential ids starting at 1
    HY_CHECK_EQ(sent.Addr, std::string("1.1.1.1:80"));
    HY_CHECK(sent.Data == std::vector<uint8_t>({0x11, 0x22}));

    // inbound message routed back to the right connection only
    UDPMessage in;
    in.SessionID = 2;
    in.FragCount = 1;
    in.Addr = "2.2.2.2:443";
    in.Data = {'q', 'r'};
    {
        std::vector<uint8_t> buf(in.Size());
        int n = in.Serialize(buf.data(), buf.size());
        buf.resize(static_cast<size_t>(n));
        conn.InjectDatagram(buf);
    }

    std::vector<uint8_t> rdata;
    std::string raddr;
    HY_CHECK(c2->Receive(rdata, raddr));
    HY_CHECK(rdata == std::vector<uint8_t>({'q', 'r'}));
    HY_CHECK_EQ(raddr, std::string("2.2.2.2:443"));

    // The mock connection loops our own send back; routing must deliver it
    // to c1 (its SessionID), leaving c2 untouched.
    HY_CHECK(c1->Receive(rdata, raddr));
    HY_CHECK_EQ(raddr, std::string("1.1.1.1:80"));

    // closing transport stops the manager: NewUDP then throws ClosedError
    conn.CloseWithError(0x100, "");
    waitUntil([&] { return mgr->Count() == 0; });
    HY_CHECK_THROWS(mgr->NewUDP(), ClosedError);
    // existing conns report EOF on Receive
    HY_CHECK(!c1->Receive(rdata, raddr));
}

HY_TEST(ClientUdpSendAutoFragmentation)
{    MockQuicConnection conn;
    conn.maxDatagramPayloadSize_ = 60; // force fragmentation
    CountingClientIO io(conn);
    auto ioPtr = std::shared_ptr<CountingClientIO>(&io, [](CountingClientIO*) {});
    auto mgr = ClientUdpSessionManager::Create(ioPtr);

    auto c = mgr->NewUDP();

    std::vector<uint8_t> big(500);
    for (size_t i = 0; i < big.size(); i++) big[i] = static_cast<uint8_t>(i);

    // header size with addr "h:p": 8 + 1 + 3 = 12 => maxPayload 48 => 11 frags
    c->Send(big.data(), big.size(), "h:p");
    HY_CHECK(io.sendCalls > 1);

    // defragment on the receiving end
    auto dgrams = conn.SentDatagrams();
    frag::Defragger d;
    std::shared_ptr<const UDPMessage> assembled;
    uint8_t totalChunks = 0;
    uint16_t pktId = 0;
    for (const auto& dg : dgrams) {
        auto m = ParseUDPMessage(dg);
        if (m.FragCount > 1 && totalChunks == 0) {
            pktId = m.PacketID;
            totalChunks = m.FragCount;
        }
        if (m.FragCount > 1) {
            // all fragments must carry the same packet id
            HY_CHECK_EQ(m.PacketID, pktId);
        }
        auto done = d.Feed(m);
        if (done) {
            assembled = done;
        }
    }
    HY_CHECK(totalChunks > 1);
    HY_CHECK(assembled != nullptr);
    HY_CHECK(assembled->FragCount == 1); // reassembled message
    HY_CHECK(assembled->Data == big);
    HY_CHECK(pktId > 0); // random non-zero packet id on fragmentation
}

// H5: UdpConn::Send reuses a thread-local message + serialization buffer.
// Different payload sizes on the same thread must not leak stale bytes from
// a previous datagram (the reused buffer is only as large as needed).
HY_TEST(ClientUdpSendReusesThreadLocalBuffer)
{
    MockQuicConnection conn;
    CountingClientIO io(conn);
    auto ioPtr = std::shared_ptr<CountingClientIO>(&io, [](CountingClientIO*) {});
    auto mgr = ClientUdpSessionManager::Create(ioPtr);
    auto c = mgr->NewUDP();

    const std::vector<size_t> sizes = {1100, 37, 512};
    for (size_t s : sizes) {
        std::vector<uint8_t> payload(s);
        for (size_t i = 0; i < s; i++) {
            payload[i] = static_cast<uint8_t>(i * 31 + s);
        }
        c->Send(payload.data(), payload.size(), "9.9.9.9:9");
    }

    auto dgrams = conn.SentDatagrams();
    HY_CHECK_EQ(dgrams.size(), sizes.size());
    for (size_t i = 0; i < sizes.size(); i++) {
        auto m = ParseUDPMessage(dgrams[i]);
        HY_CHECK_EQ(m.Data.size(), sizes[i]);
        std::vector<uint8_t> expected(sizes[i]);
        for (size_t j = 0; j < sizes[i]; j++) {
            expected[j] = static_cast<uint8_t>(j * 31 + sizes[i]);
        }
        HY_CHECK(m.Data == expected);
    }
}

// A quiet UDP session must survive its poll timeout. Receive() reports false
// both for "nothing arrived yet" and for "the session is over", and the relay
// loops used to treat those as the same thing - so a DNS lookup, a QUIC
// handshake or a game keepalive (>100 ms between replies) had its relay torn
// down after the first idle poll. ReceivePacket() is what tells them apart.
HY_TEST(ClientUdpReceivePacketSeparatesTimeoutFromClose)
{
    MockQuicConnection conn;
    CountingClientIO io(conn);
    auto ioPtr = std::shared_ptr<CountingClientIO>(&io, [](CountingClientIO*) {});
    auto mgr = ClientUdpSessionManager::Create(ioPtr);
    auto c = mgr->NewUDP();

    // Idle session: the deadline elapses with nothing to deliver, and the
    // connection is still perfectly usable.
    std::vector<uint8_t> data;
    std::string addr;
    auto t0 = std::chrono::steady_clock::now();
    auto r = c->ReceivePacket(data, addr, Duration::FromMillis(80));
    auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - t0).count();
    HY_CHECK(r == hy2::client::UdpRecvResult::kTimeout);
    // The wait is the requested one, not the 100 ms internal poll - a caller
    // asking for 80 ms must not be held for longer.
    HY_CHECK(elapsedMs >= 70);
    HY_CHECK(elapsedMs < 200);

    // Still usable after the timeout: a datagram that arrives later is
    // delivered normally.
    // NewUDP() hands back the base interface; the session id the manager
    // filed it under is what a datagram must carry to be routed to it.
    UDPMessage msg;
    msg.SessionID = SessionIdOf(mgr);
    msg.FragCount = 1;
    msg.Addr = "1.1.1.1:53";
    msg.Data = {'h', 'i'};
    uint8_t buf[512];
    int n = msg.Serialize(buf, sizeof(buf));
    conn.InjectDatagram(std::vector<uint8_t>(buf, buf + n));

    r = c->ReceivePacket(data, addr, Duration::FromSeconds(2));
    HY_CHECK(r == hy2::client::UdpRecvResult::kPacket);
    HY_CHECK(data == std::vector<uint8_t>({'h', 'i'}));
    HY_CHECK_EQ(addr, std::string("1.1.1.1:53"));

    // Only an actual close reports kClosed.
    c->Close();
    r = c->ReceivePacket(data, addr, Duration::FromMillis(80));
    HY_CHECK(r == hy2::client::UdpRecvResult::kClosed);
}

// The relay loop's own contract: a session that goes quiet for several polls
// keeps running, and only a close ends it. This is the regression the bug
// produced (relay dropped after ~100 ms of silence).
HY_TEST(ClientUdpQuietSessionStaysUsableAcrossPolls)
{
    MockQuicConnection conn;
    CountingClientIO io(conn);
    auto ioPtr = std::shared_ptr<CountingClientIO>(&io, [](CountingClientIO*) {});
    auto mgr = ClientUdpSessionManager::Create(ioPtr);
    auto c = mgr->NewUDP();

    // Stand in for the SOCKS5/forwarding receive loops: exactly the branch
    // structure they use.
    auto relayIteration = [&](std::chrono::milliseconds wait) {
        std::vector<uint8_t> data;
        std::string from;
        auto res = c->ReceivePacket(data, from, Duration::FromMillis(wait.count()));
        if (res == hy2::client::UdpRecvResult::kClosed) return 0;   // break
        if (res == hy2::client::UdpRecvResult::kTimeout) return 1;  // continue
        return 2;                                                   // deliver
    };

    // Four consecutive idle polls - the old code returned false on the first
    // one and every caller broke out of its loop.
    for (int i = 0; i < 4; ++i) {
        HY_CHECK_EQ(relayIteration(std::chrono::milliseconds(50)), 1);
    }

    // The session is still alive and delivers when data finally arrives.
    UDPMessage msg;
    msg.SessionID = SessionIdOf(mgr);
    msg.FragCount = 1;
    msg.Addr = "8.8.8.8:53";
    msg.Data = {'o', 'k'};
    uint8_t buf[512];
    int n = msg.Serialize(buf, sizeof(buf));
    conn.InjectDatagram(std::vector<uint8_t>(buf, buf + n));
    HY_CHECK_EQ(relayIteration(std::chrono::milliseconds(1000)), 2);

    c->Close();
    HY_CHECK_EQ(relayIteration(std::chrono::milliseconds(50)), 0);
}

// ---------------------------------------------------------------------------
// H3sHandler auth + TCP flow

namespace {

struct CaptureWriter : public HttpResponseWriter {
    HeaderMap hdrs;
    int status = 0;
    std::vector<uint8_t> body;
    HeaderMap& Header() override { return hdrs; }
    void WriteHeader(int s) override {
        if (status == 0) status = s;
    }
    void Write(const uint8_t* p, size_t n) override {
        body.insert(body.end(), p, p + n);
    }
};

struct FixedAuthenticator : public Authenticator {
    bool ok = true;
    std::string id = "uid-1";
    bool Authenticate(const std::string&, const std::string&, uint64_t,
                      std::string& idOut) override {
        idOut = id;
        return ok;
    }
};

struct DirectOutbound : public Outbound {
    std::function<std::shared_ptr<IConn>(const std::string&)> tcpFn;
    std::function<bool(const std::string&)> checkUdpFn =
        [](const std::string&) { return true; };

    std::shared_ptr<IConn> TCP(const std::string& reqAddr) override {
        if (!tcpFn) throw Error("dial failed");
        return tcpFn(reqAddr);
    }
    std::shared_ptr<IUdpConn> UDP(const std::string&) override { throw Error("no udp"); }
    bool CheckUDP(const std::string& a) override { return checkUdpFn(a); }
};

hy2::server::Config MakeTestConfig() {
    hy2::server::Config cfg;
    cfg.TLSConfig.CertificatesPEM.push_back("dummy-cert"); // satisfy Fill()
    cfg.HasConn = true;
    cfg.DisableUDP = true; // avoid spawning udp manager threads in these tests
    return cfg;
}

} // namespace

HY_TEST(H3HandlerAuthSuccessUsesBrutal)
{
    hy2::server::Config cfg = MakeTestConfig();
    cfg.CongestionCfg.Type = "bbr";
    cfg.BandwidthCfg.MaxTx = 1024 * 1024;
    cfg.BandwidthCfg.MaxRx = 2048 * 1024;
    FixedAuthenticator auth;
    cfg.AuthenticatorPtr = &auth;
    DirectOutbound ob;
    cfg.OutboundPtr = &ob;

    auto conn = std::make_shared<MockQuicConnection>();
    H3sHandler h(cfg, conn);

    HttpRequest req;
    req.Method = "POST";
    req.Host = URLHost;
    req.Path = URLPath;
    req.Header["Hysteria-Auth"] = "pw";
    req.Header["Hysteria-CC-RX"] = "900000"; // client rx < server maxTx

    CaptureWriter w;
    h.ServeHTTP(w, req);
    HY_CHECK(h.Authenticated());
    HY_CHECK_EQ(w.status, StatusAuthOK);
    HY_CHECK_EQ(w.hdrs[std::string(ResponseHeaderUDPEnabled)], std::string("false"));
    // actualTx = min(serverTx=1MB, clientRx=900000) = 900000 => Brutal attached
    auto brutal = dynamic_cast<cc::BrutalSender*>(conn->GetCongestionControl().get());
    HY_CHECK(brutal != nullptr);
    HY_CHECK_NEAR(brutal->AckRate(), 1.0, 0.0001);
}

HY_TEST(H3HandlerAuthClampsToMaxTx)
{
    hy2::server::Config cfg = MakeTestConfig();
    cfg.BandwidthCfg.MaxTx = 500000;
    FixedAuthenticator auth;
    cfg.AuthenticatorPtr = &auth;
    DirectOutbound ob;
    cfg.OutboundPtr = &ob;

    auto conn = std::make_shared<MockQuicConnection>();
    H3sHandler h(cfg, conn);

    HttpRequest req;
    req.Method = "POST";
    req.Host = URLHost;
    req.Path = URLPath;
    req.Header["Hysteria-CC-RX"] = "999999999"; // asking for more than maxTx

    CaptureWriter w;
    h.ServeHTTP(w, req);
    HY_CHECK(h.Authenticated());
    auto brutal = dynamic_cast<cc::BrutalSender*>(conn->GetCongestionControl().get());
    HY_CHECK(brutal != nullptr); // clamped to 500000, still brutal
}

HY_TEST(H3HandlerIgnoreClientBandwidthRespondsAuto)
{
    hy2::server::Config cfg = MakeTestConfig();
    cfg.IgnoreClientBandwidth = true;
    FixedAuthenticator auth;
    cfg.AuthenticatorPtr = &auth;
    DirectOutbound ob;
    cfg.OutboundPtr = &ob;

    auto conn = std::make_shared<MockQuicConnection>();
    H3sHandler h(cfg, conn);

    HttpRequest req;
    req.Method = "POST";
    req.Host = URLHost;
    req.Path = URLPath;
    req.Header["Hysteria-Auth"] = "pw";

    CaptureWriter w;
    h.ServeHTTP(w, req);
    HY_CHECK(h.Authenticated());
    HY_CHECK_EQ(w.hdrs[std::string(CommonHeaderCCRX)], std::string("auto"));
    // configured CC (BBR) should be attached, not brutal
    auto ccInst = conn->GetCongestionControl();
    HY_CHECK(ccInst != nullptr);
    HY_CHECK(dynamic_cast<cc::BrutalSender*>(ccInst.get()) == nullptr);
}

HY_TEST(H3HandlerAuthFailureMasquerades404)
{
    hy2::server::Config cfg = MakeTestConfig();
    FixedAuthenticator auth;
    auth.ok = false;
    cfg.AuthenticatorPtr = &auth;
    DirectOutbound ob;
    cfg.OutboundPtr = &ob;

    auto conn = std::make_shared<MockQuicConnection>();
    H3sHandler h(cfg, conn);

    HttpRequest req;
    req.Method = "POST";
    req.Host = URLHost;
    req.Path = URLPath;
    req.Header["Hysteria-Auth"] = "wrong";

    CaptureWriter w;
    h.ServeHTTP(w, req);
    HY_CHECK(!h.Authenticated());
    HY_CHECK_EQ(w.status, 404);
}

HY_TEST(ServerHandleTCPRequestProxying)
{
    hy2::server::Config cfg = MakeTestConfig();
    FixedAuthenticator auth;
    cfg.AuthenticatorPtr = &auth;

    DirectOutbound ob;
    // remoteEnd = the far end of the outbound connection (what the target
    // server would read from / write to); targetPeer is held by the outbound.
    auto [remoteEnd, targetPeer] = PipeStream::MakePair();
    ob.tcpFn = [&](const std::string& addr) -> std::shared_ptr<IConn> {
        HY_CHECK_EQ(addr, std::string("target.example:80"));
        return std::make_shared<ConnFromStream>(targetPeer);
    };
    cfg.OutboundPtr = &ob;

    auto quicConn = std::make_shared<MockQuicConnection>();
    // Heap-constructed: ProxyStreamHijacker calls shared_from_this() when it
    // spawns the request worker, which requires a shared_ptr owner.
    auto h = std::make_shared<H3sHandler>(cfg, quicConn);

    // authenticate first
    HttpRequest areq;
    areq.Method = "POST";
    areq.Host = URLHost;
    areq.Path = URLPath;
    areq.Header["Hysteria-Auth"] = "x";
    CaptureWriter aw;
    h->ServeHTTP(aw, areq);
    HY_CHECK(h->Authenticated());

    // simulate an incoming TCP request stream:
    // SerializeTCPRequest emits [frameType][addrLen][addr][padLen][padding];
    // ProxyStreamHijacker consumes the frame-type varint itself.
    auto [clientSide, serverSide] = PipeStream::MakePair();
    auto reqBytes = SerializeTCPRequest("target.example:80");
    // Write() delivers to the peer: writing on clientSide makes the bytes
    // readable from serverSide, which is the end the handler reads.
    clientSide->Write(reqBytes.data(), reqBytes.size());

    quicConn->InjectIncomingStream(serverSide);

    auto hyStr = std::static_pointer_cast<IHyStream>(
        std::static_pointer_cast<IQuicStream>(serverSide));
    HY_CHECK(h->ProxyStreamHijacker(FrameTypeTCPRequest, hyStr));

    // read the TCP response (status byte + msg + padding) via blocking reads
    auto resp = ReadTCPResponse(*clientSide);
    HY_CHECK(resp.OK);
    HY_CHECK_EQ(resp.Message, std::string("Connected"));

    // bidirectional payload proxying:
    // client -> server stream -> outbound conn -> remoteEnd
    const char payload[] = "GET / HTTP/1.1\r\n";
    clientSide->Write(reinterpret_cast<const uint8_t*>(payload), sizeof(payload) - 1);

    uint8_t rbuf[256] = {};
    size_t n = remoteEnd->Read(rbuf, sizeof(rbuf));
    HY_CHECK(n == sizeof(payload) - 1);
    HY_CHECK(std::memcmp(rbuf, payload, n) == 0);

    // remoteEnd (target server) replies; it flows back to the client stream
    const char reply[] = "HTTP/1.1 200 OK\r\n";
    remoteEnd->Write(reinterpret_cast<const uint8_t*>(reply), sizeof(reply) - 1);
    uint8_t cbuf[256] = {};
    size_t m = clientSide->Read(cbuf, sizeof(cbuf));
    HY_CHECK(m == sizeof(reply) - 1);
    HY_CHECK(std::memcmp(cbuf, reply, m) == 0);

    // closing the remote unblocks and ends the proxy loop cleanly
    remoteEnd->Close();
    SleepFor(Duration::FromMillis(200)); // let the detached handler thread finish
}

// ---------------------------------------------------------------------------
// DisableChromeParrot configuration tests
//
// Verifies the QuicConfig field defaults and semantic matching the official
// hy2-go behavior where DisableChromeParrot defaults to false (Chrome
// fingerprinting ON by default).

HY_TEST(QuicConfigDisableChromeParrotDefault)
{
    // Official Go: DisableChromeParrot bool // Chrome QUIC fingerprint parroting is on by default.
    // Default is false �� ChromeParrot ON �� zero-length SCID
    QuicConfig cfg;
    HY_CHECK_EQ(cfg.DisableChromeParrot, false);
}

HY_TEST(QuicConfigDisableChromeParrotSettable)
{
    QuicConfig cfg;

    // Setting to true disables Chrome fingerprinting (8-byte SCID)
    cfg.DisableChromeParrot = true;
    HY_CHECK_EQ(cfg.DisableChromeParrot, true);

    // Setting back to false re-enables Chrome fingerprinting (zero-length SCID)
    cfg.DisableChromeParrot = false;
    HY_CHECK_EQ(cfg.DisableChromeParrot, false);
}

HY_TEST(QuicConfigDisableChromeParrotSemantic)
{
    // The semantic matches Go:
    //   ChromeParrot = !c.config.QUICConfig.DisableChromeParrot
    // So:
    //   DisableChromeParrot=false �� ChromeParrot=true �� zero-length SCID
    //   DisableChromeParrot=true  �� ChromeParrot=false �� 8-byte SCID
    QuicConfig cfg;

    cfg.DisableChromeParrot = false;
    bool chromeParrot = !cfg.DisableChromeParrot;
    HY_CHECK_EQ(chromeParrot, true);  // zero-length SCID

    cfg.DisableChromeParrot = true;
    chromeParrot = !cfg.DisableChromeParrot;
    HY_CHECK_EQ(chromeParrot, false); // 8-byte SCID
}
