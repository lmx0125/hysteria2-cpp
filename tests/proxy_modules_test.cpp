// proxy_modules_test.cpp - Tests for SOCKS5, HTTP, and Forwarding proxy modules.
#include "hytest.hpp"
#include "hy2/proxy/socks5/socks5_server.hpp"
#include "hy2/proxy/http/http_server.hpp"
#include "hy2/proxy/forwarding/forwarding.hpp"
#include "hy2/proxy/proxymux/proxymux.hpp"

// ---------------------------------------------------------------------------
// SOCKS5 Server tests

using namespace hy2::proxy::socks5;

HY_TEST(Socks5_ParseSocks5Address_IPv4) {
    uint8_t addr[4] = {192, 168, 1, 1};
    uint8_t port[2] = {0x00, 0x50}; // port 80
    std::string result = parseSocks5Address(kAtypIPv4, addr, 4, port);
    HY_CHECK(result == "192.168.1.1:80");
}

HY_TEST(Socks5_ParseSocks5Address_Domain) {
    uint8_t addr[] = {11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    uint8_t port[2] = {0x01, 0xBB}; // port 443
    std::string result = parseSocks5Address(kAtypDomain, addr, 12, port);
    HY_CHECK(result == "example.com:443");
}

HY_TEST(Socks5_BuildSocks5Address_IPv4) {
    auto result = buildSocks5Address("192.168.1.1:80");
    HY_CHECK(result.size() == 7); // ATYP(1) + IPv4(4) + Port(2)
    HY_CHECK(result[0] == kAtypIPv4);
    HY_CHECK(result[5] == 0x00);
    HY_CHECK(result[6] == 0x50);
}

HY_TEST(Socks5_BuildSocks5Address_Domain) {
    auto result = buildSocks5Address("example.com:443");
    HY_CHECK(result[0] == kAtypDomain);
    HY_CHECK(result[1] == 11); // domain length
    HY_CHECK(result[2] == 'e');
}

HY_TEST(Socks5_Constants) {
    HY_CHECK(kCmdConnect == 0x01);
    HY_CHECK(kCmdUDP == 0x03);
    HY_CHECK(kMethodNone == 0x00);
    HY_CHECK(kMethodUsernamePassword == 0x02);
    HY_CHECK(kRepSuccess == 0x00);
    HY_CHECK(kRepHostUnreachable == 0x04);
}

// ---------------------------------------------------------------------------
// HTTP Server tests

using namespace hy2::proxy::http;

HY_TEST(Http_ParseHttpRequestTarget) {
    std::string target = parseHttpRequestTarget("CONNECT example.com:443 HTTP/1.1");
    HY_CHECK(target == "example.com:443");
}

HY_TEST(Http_ParseHttpRequestTarget_NoPort) {
    std::string target = parseHttpRequestTarget("CONNECT example.com HTTP/1.1");
    HY_CHECK(target == "example.com");
}

HY_TEST(Http_ParseProxyAuth) {
    // "user:pass" base64 encoded = "dXNlcjpwYXNz"
    auto [user, pass] = parseProxyAuth("Basic dXNlcjpwYXNz");
    HY_CHECK(user == "user");
    HY_CHECK(pass == "pass");
}

HY_TEST(Http_ParseProxyAuth_Empty) {
    auto [user, pass] = parseProxyAuth("");
    HY_CHECK(user.empty());
    HY_CHECK(pass.empty());
}

HY_TEST(Http_ParseProxyAuth_Invalid) {
    auto [user, pass] = parseProxyAuth("Bearer token");
    HY_CHECK(user.empty());
    HY_CHECK(pass.empty());
}

// ---------------------------------------------------------------------------
// Forwarding tests

using namespace hy2::proxy::forwarding;

HY_TEST(Forwarding_UdpSessionEntry) {
    // Basic construction test
    UdpSessionEntry entry;
    HY_CHECK(entry.LastActiveNs.load() == 0);
    HY_CHECK(entry.Timeout.load() == false);
}

// ---------------------------------------------------------------------------
// ProxyMux tests

using namespace hy2::proxy::proxymux;

HY_TEST(ProxyMux_SubListener) {
    SubListener sl;
    HY_CHECK(sl.IsClosed() == false);
    sl.Close();
    HY_CHECK(sl.IsClosed() == true);
    // Second close should be idempotent
    sl.Close();
    HY_CHECK(sl.IsClosed() == true);
}

HY_TEST(ProxyMux_MuxManager_Singleton) {
    auto& m1 = MuxManager::Instance();
    auto& m2 = MuxManager::Instance();
    HY_CHECK(&m1 == &m2);
}
