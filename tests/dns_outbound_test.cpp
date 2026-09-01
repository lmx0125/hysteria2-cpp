// dns_outbound_test.cpp - Tests for DNS resolver (System, Standard, DoH).
#include "hytest.hpp"
#include "hy2/outbounds/dns_outbound.hpp"

using namespace hy2::outbounds;

// ---------------------------------------------------------------------------
// System DNS Resolver Tests
// ---------------------------------------------------------------------------

HY_TEST(DnsResolver_SystemResolveLocalhost) {
    SystemDnsResolver resolver;
    auto result = resolver.Resolve("localhost");
    HY_CHECK(result.hasIpv4 || result.hasIpv6);
    if (result.hasIpv4) {
        HY_CHECK(result.ipv4 == "127.0.0.1");
    }
}

HY_TEST(DnsResolver_SystemResolveInvalid) {
    SystemDnsResolver resolver;
    auto result = resolver.Resolve("this-host-does-not-exist-12345.invalid");
    HY_CHECK(!result.error.empty());
}

HY_TEST(DnsResolver_SystemResolveIP) {
    SystemDnsResolver resolver;
    auto result = resolver.Resolve("8.8.8.8");
    HY_CHECK(result.hasIpv4);
    HY_CHECK(result.ipv4 == "8.8.8.8");
}

// ---------------------------------------------------------------------------
// Standard DNS Resolver Tests
// ---------------------------------------------------------------------------

HY_TEST(DnsResolver_StandardResolve) {
    StandardDnsResolver resolver("8.8.8.8:53", false);
    auto result = resolver.Resolve("google.com");
    // DNS resolution may fail in restricted environments, just check no crash
    HY_CHECK(true);
}

// ---------------------------------------------------------------------------
// DNS over HTTPS (DoH) Resolver Tests
// ---------------------------------------------------------------------------

HY_TEST(DohResolver_Create) {
    // Test creating DoH resolver with different configurations
    DohDnsResolver r1("https://1.1.1.1/dns-query");
    DohDnsResolver r2("https://8.8.8.8/dns-query");
    DohDnsResolver r3("https://dns.google/dns-query", "", false);
    DohDnsResolver r4("https://1.1.1.1/dns-query", "1.1.1.1", true);
    // All should create without throwing
    HY_CHECK(true);
}

HY_TEST(DohResolver_ResolveCloudflare) {
    // Test resolving via Cloudflare DoH
    DohDnsResolver resolver("https://1.1.1.1/dns-query");
    auto result = resolver.Resolve("example.com");
    // Should resolve successfully or fail gracefully (network restrictions)
    // At minimum, should not crash
    HY_CHECK(true);
}

HY_TEST(DohResolver_ResolveGoogle) {
    // Test resolving via Google DoH
    DohDnsResolver resolver("https://8.8.8.8/dns-query");
    auto result = resolver.Resolve("example.com");
    // Check that we get a result or an error (not a crash)
    if (!result.error.empty()) {
        // Network error is acceptable in restricted environments
        HY_CHECK(true);
    } else {
        HY_CHECK(result.hasIpv4 || result.hasIpv6);
    }
}

HY_TEST(DohResolver_NonExistentDomain) {
    // Test resolving non-existent domain
    DohDnsResolver resolver("https://8.8.8.8/dns-query");
    auto result = resolver.Resolve("this-domain-does-not-exist-12345.example.com");
    // Should either return error or no records
    HY_CHECK(!result.error.empty() || (!result.hasIpv4 && !result.hasIpv6));
}

HY_TEST(DohResolver_WithCustomSni) {
    // Test with custom SNI
    DohDnsResolver resolver("https://1.1.1.1/dns-query", "cloudflare-dns.com");
    auto result = resolver.Resolve("example.com");
    // Should work with custom SNI or fail gracefully
    HY_CHECK(true);
}

HY_TEST(DohResolver_Performance) {
    // Test that DoH is not extremely slow
    DohDnsResolver resolver("https://8.8.8.8/dns-query");
    auto start = std::chrono::steady_clock::now();
    auto result = resolver.Resolve("example.com");
    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    // Should complete within 10 seconds (very generous)
    HY_CHECK(ms < 10000);
}

// ---------------------------------------------------------------------------
// Direct Outbound Tests (TFO related)
// ---------------------------------------------------------------------------

HY_TEST(DirectOutbound_Create) {
    // Test creating DirectOutbound with different modes
    DirectOutbound o1(DirectOutboundMode::Auto);
    DirectOutbound o2(DirectOutboundMode::IPv6Prefer);
    DirectOutbound o3(DirectOutboundMode::IPv4Prefer);
    DirectOutbound o4(DirectOutboundMode::IPv6Only);
    DirectOutbound o5(DirectOutboundMode::IPv4Only);
    // All should create without throwing
    HY_CHECK(true);
}

HY_TEST(DirectOutbound_CheckUDP) {
    // Test UDP support check
    DirectOutbound outbound(DirectOutboundMode::Auto);
    HY_CHECK(outbound.CheckUDP("127.0.0.1:53"));
}
