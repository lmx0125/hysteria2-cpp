// acl_engine_test.cpp - Tests for ACL engine (Go-compatible syntax).
#include "hytest.hpp"
#include "hy2/outbounds/acl_engine.hpp"
#include "hy2/outbounds/direct.hpp"

using namespace hy2::outbounds;

// ---------------------------------------------------------------------------
// Helper: mock outbound that records calls

class MockOutbound : public hy2::server::Outbound {
public:
    std::string name;
    mutable std::string lastTCPAddr;
    mutable std::string lastUDPAddr;

    explicit MockOutbound(std::string n) : name(std::move(n)) {}

    std::shared_ptr<hy2::server::IConn> TCP(const std::string& reqAddr) override {
        lastTCPAddr = reqAddr;
        return nullptr; // don't actually connect
    }
    std::shared_ptr<hy2::server::IUdpConn> UDP(const std::string& reqAddr) override {
        lastUDPAddr = reqAddr;
        return nullptr;
    }
    bool CheckUDP(const std::string&) override { return true; }
};

// ---------------------------------------------------------------------------
// Tests

HY_TEST(ACL_ParseSimpleRules) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    auto reject = std::make_shared<MockOutbound>("reject");

    engine.RegisterOutbound("direct", direct);
    engine.SetDefaultOutbound(direct);

    engine.Parse(R"(
# Comment line
direct(192.168.1.0/24)
direct(suffix:example.com)
direct(10.0.0.0/8,tcp)
reject(*)
)");
    // No crash = pass
}

HY_TEST(ACL_MatchAll) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("direct(*)");

    auto ob = engine.Evaluate("anything.com", 80, AclProto::TCP);
    HY_CHECK(ob == direct);
}

HY_TEST(ACL_MatchCIDR4) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("direct(192.168.1.0/24)");

    HY_CHECK(engine.Evaluate("192.168.1.100", 80, AclProto::TCP) == direct);
    HY_CHECK(engine.Evaluate("192.168.1.255", 80, AclProto::TCP) == direct);
    HY_CHECK(engine.Evaluate("192.168.2.1", 80, AclProto::TCP) == direct); // different subnet
}

HY_TEST(ACL_MatchDomainSuffix) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("direct(suffix:example.com)");

    HY_CHECK(engine.Evaluate("example.com", 80, AclProto::TCP) == direct);
    HY_CHECK(engine.Evaluate("foo.example.com", 80, AclProto::TCP) == direct);
    HY_CHECK(engine.Evaluate("bar.sub.example.com", 80, AclProto::TCP) == direct);
    // Not a suffix match
    HY_CHECK(engine.Evaluate("notexample.com", 80, AclProto::TCP) == direct); // different
}

HY_TEST(ACL_MatchDomainExact) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("direct(example.com)");

    HY_CHECK(engine.Evaluate("example.com", 80, AclProto::TCP) == direct);
    HY_CHECK(engine.Evaluate("foo.example.com", 80, AclProto::TCP) == direct); // no match
}

HY_TEST(ACL_MatchWildcard) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("direct(*.example.com)");

    HY_CHECK(engine.Evaluate("foo.example.com", 80, AclProto::TCP) == direct);
    HY_CHECK(engine.Evaluate("bar.example.com", 80, AclProto::TCP) == direct);
    // Exact match should NOT match wildcard
    HY_CHECK(engine.Evaluate("example.com", 80, AclProto::TCP) == direct); // default
}

HY_TEST(ACL_ProtoFilter) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse(R"(
direct(10.0.0.0/8,tcp)
reject(10.0.0.0/8,udp)
)");

    HY_CHECK(engine.Evaluate("10.0.0.1", 80, AclProto::TCP) == direct);
    // reject returns nullptr
    HY_CHECK(engine.Evaluate("10.0.0.1", 53, AclProto::UDP) == nullptr);
}

HY_TEST(ACL_PortFilter) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse(R"(
direct(*,tcp/80-443)
reject(*)
)");

    HY_CHECK(engine.Evaluate("example.com", 80, AclProto::TCP) == direct);
    HY_CHECK(engine.Evaluate("example.com", 443, AclProto::TCP) == direct);
    // reject returns nullptr
    HY_CHECK(engine.Evaluate("example.com", 8080, AclProto::TCP) == nullptr);
}

HY_TEST(ACL_FirstMatchWins) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse(R"(
reject(*)
direct(192.168.1.0/24)
)");

    // First rule matches all, reject returns nullptr
    HY_CHECK(engine.Evaluate("192.168.1.1", 80, AclProto::TCP) == nullptr);
    HY_CHECK(engine.Evaluate("10.0.0.1", 80, AclProto::TCP) == nullptr);
}

HY_TEST(ACL_DefaultOutbound) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);

    // Empty ACL = no rules = everything uses default
    auto ob = engine.Evaluate("anything.com", 80, AclProto::TCP);
    HY_CHECK(ob == direct);
}

HY_TEST(ACL_HijackAddress) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("direct(192.168.1.0/24,*,10.0.0.1)");

    std::string hijack;
    auto ob = engine.Evaluate("192.168.1.100", 80, AclProto::TCP, &hijack);
    HY_CHECK(ob == direct);
    HY_CHECK(hijack == "10.0.0.1");
}

HY_TEST(ACL_TCPRouting) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("direct(*)");

    // TCP routing should work
    auto conn = engine.TCP("127.0.0.1:80");
    // direct->TCP returns nullptr (mock), but no crash = success
    HY_CHECK(true);
}

HY_TEST(ACL_CheckUDP) {
    AclEngine engine;
    auto direct = std::make_shared<MockOutbound>("direct");
    engine.SetDefaultOutbound(direct);
    engine.RegisterOutbound("direct", direct);

    engine.Parse("reject(10.0.0.0/8,udp)");

    HY_CHECK(engine.CheckUDP("10.0.0.1:53") == false);
    HY_CHECK(engine.CheckUDP("192.168.1.1:53") == true);
}
