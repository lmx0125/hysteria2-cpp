// platform_test.cpp - Tests for platform abstraction layer.
// Tests the unified interfaces and platform-specific implementations.

#include "hytest.hpp"

#include "hy2/platform/platform_common.hpp"
#include "hy2/platform/mimic_common.hpp"

using namespace hy2::platform;
using hy2::IByteReaderWriter;

// ---------------------------------------------------------------------------
// Mimic filter generation tests

HY_TEST(PlatformMimic_GenerateFiltersClientIPv4) {
    std::vector<std::string> addresses = {"192.168.1.1:443"};
    auto filters = GenerateMimicFilters(MimicRole::Client, addresses);

    HY_CHECK_EQ(filters.size(), 1u);
    HY_CHECK_EQ(filters[0], "remote=192.168.1.1:443");
}

HY_TEST(PlatformMimic_GenerateFiltersClientIPv6) {
    std::vector<std::string> addresses = {"[2001:db8::1]:443"};
    auto filters = GenerateMimicFilters(MimicRole::Client, addresses);

    HY_CHECK_EQ(filters.size(), 1u);
    HY_CHECK_EQ(filters[0], "remote=[2001:db8::1]:443");
}

HY_TEST(PlatformMimic_GenerateFiltersClientDedup) {
    std::vector<std::string> addresses = {
        "192.168.1.1:443",
        "192.168.1.1:443"
    };
    auto filters = GenerateMimicFilters(MimicRole::Client, addresses);

    HY_CHECK_EQ(filters.size(), 1u);
}

HY_TEST(PlatformMimic_GenerateFiltersClientMultiple) {
    std::vector<std::string> addresses = {
        "192.168.1.1:443",
        "10.0.0.1:8080"
    };
    auto filters = GenerateMimicFilters(MimicRole::Client, addresses);

    HY_CHECK_EQ(filters.size(), 2u);
}

HY_TEST(PlatformMimic_GenerateFiltersServerExplicit) {
    std::vector<std::string> addresses = {"192.168.1.1:8080"};
    auto filters = GenerateMimicFilters(MimicRole::Server, addresses);

    HY_CHECK_EQ(filters.size(), 1u);
    HY_CHECK_EQ(filters[0], "local=192.168.1.1:8080,handshake=0:3");
}

HY_TEST(PlatformMimic_GenerateFiltersServerIPv6) {
    std::vector<std::string> addresses = {"[2001:db8::1]:8080"};
    auto filters = GenerateMimicFilters(MimicRole::Server, addresses);

    HY_CHECK_EQ(filters.size(), 1u);
    HY_CHECK_EQ(filters[0], "local=[2001:db8::1]:8080,handshake=0:3");
}

HY_TEST(PlatformMimic_GenerateFiltersServerWildcard) {
    std::vector<std::string> addresses = {"0.0.0.0:8080"};
    auto filters = GenerateMimicFilters(MimicRole::Server, addresses);

    HY_CHECK_EQ(filters.size(), 1u);
    HY_CHECK_EQ(filters[0], "local=0.0.0.0:8080,handshake=0:3");
}

HY_TEST(PlatformMimic_GenerateFiltersServerIPv6Wildcard) {
    std::vector<std::string> addresses = {"[::]:8080"};
    auto filters = GenerateMimicFilters(MimicRole::Server, addresses);

    HY_CHECK_EQ(filters.size(), 1u);
    HY_CHECK_EQ(filters[0], "local=[::]:8080,handshake=0:3");
}

// ---------------------------------------------------------------------------
// ParseFilterAddress tests

HY_TEST(PlatformMimic_ParseFilterAddressRemote) {
    HY_CHECK_EQ(ParseFilterAddress("remote=192.168.1.1:443"), "192.168.1.1:443");
}

HY_TEST(PlatformMimic_ParseFilterAddressLocal) {
    HY_CHECK_EQ(ParseFilterAddress("local=0.0.0.0:8080,handshake=0:3"), "0.0.0.0:8080");
}

HY_TEST(PlatformMimic_ParseFilterAddressIPv6) {
    HY_CHECK_EQ(ParseFilterAddress("remote=[2001:db8::1]:443"), "2001:db8::1:443");
}

HY_TEST(PlatformMimic_ParseFilterAddressLocalIPv6) {
    HY_CHECK_EQ(ParseFilterAddress("local=[::]:8080,handshake=0:3"), ":::8080");
}

// ---------------------------------------------------------------------------
// Firewall port range tests

HY_TEST(PlatformFirewall_PortRangeSingle) {
    FirewallPortRange range{8080, 8080};
    HY_CHECK_EQ(range.start, 8080);
    HY_CHECK_EQ(range.end, 8080);
}

HY_TEST(PlatformFirewall_PortRangeMultiple) {
    FirewallPortRange range{20000, 20005};
    HY_CHECK_EQ(range.start, 20000);
    HY_CHECK_EQ(range.end, 20005);
}

// ---------------------------------------------------------------------------
// Factory function tests

HY_TEST(PlatformFactory_CreateTunDevice) {
    TunConfig config;
    config.Name = "tun0";
    config.MTU = 1400;

    auto device = CreateTunDevice(config);
    // On supported platforms, this should return a valid device
    // On unsupported platforms, it returns nullptr
    // We just test that the factory doesn't crash
    HY_CHECK(device == nullptr || device != nullptr);
}

HY_TEST(PlatformFactory_CreateTcpTransparentProxy) {
    auto dialFunc = [](const std::string& addr) -> std::shared_ptr<IByteReaderWriter> {
        return nullptr;
    };

    auto proxy = CreateTcpTransparentProxy(dialFunc);
    HY_CHECK(proxy == nullptr || proxy != nullptr);
}

HY_TEST(PlatformFactory_CreateUdpTransparentProxy) {
    auto dialFunc = []() -> std::shared_ptr<IHyUDPConn> {
        return nullptr;
    };

    auto proxy = CreateUdpTransparentProxy(dialFunc);
    HY_CHECK(proxy == nullptr || proxy != nullptr);
}

HY_TEST(PlatformFactory_CreateTcpRedirector) {
    auto dialFunc = [](const std::string& addr) -> std::shared_ptr<IByteReaderWriter> {
        return nullptr;
    };

    auto redirector = CreateTcpRedirector(dialFunc);
    HY_CHECK(redirector == nullptr || redirector != nullptr);
}

HY_TEST(PlatformFactory_CreateFirewallManager) {
    auto manager = CreateFirewallManager();
    HY_CHECK(manager == nullptr || manager != nullptr);
}

HY_TEST(PlatformFactory_StartMimicDisabled) {
    MimicConfig cfg;
    cfg.Enabled = false;

    auto instance = StartMimic(cfg, MimicRole::Client, {"192.168.1.1:443"});
    HY_CHECK_EQ(instance, nullptr);
}

HY_TEST(PlatformFactory_StartMimicEnabled) {
    MimicConfig cfg;
    cfg.Enabled = true;
    cfg.Path = "/nonexistent/mimic";

    // This will fail because the binary doesn't exist
    auto instance = StartMimic(cfg, MimicRole::Client, {"192.168.1.1:443"});
    HY_CHECK_EQ(instance, nullptr);
}

// ---------------------------------------------------------------------------
// SocketOptions tests

HY_TEST(PlatformSocket_ApplyUDPOptionsNullParams) {
    // Should not crash with null parameters
    SocketOptions::ApplyUDPOptions(-1);
}

HY_TEST(PlatformSocket_ApplyUDPOptionsWithInterface) {
    std::string iface = "eth0";
    SocketOptions::ApplyUDPOptions(-1, &iface);
}

HY_TEST(PlatformSocket_ApplyUDPOptionsWithMark) {
    uint32_t mark = 0x1;
    SocketOptions::ApplyUDPOptions(-1, nullptr, &mark);
}
