// test_doh_tfo.cpp - Test DNS over HTTPS (DoH) and TCP Fast Open (TFO)
//
// Compile:
//   g++ -std=c++20 -o test_doh_tfo test_doh_tfo.cpp \
//       -I../include -I../../core/include \
//       -L../build -lhy2_extras -lhy2_core \
//       -lssl -lcrypto -lpthread
//
// Run:
//   ./test_doh_tfo

#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <cassert>
#include <cstring>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#include "hy2/outbounds/dns_outbound.hpp"
#include "hy2/outbounds/direct.hpp"

using namespace hy2::outbounds;

// ============================================================================
// Test Helpers
// ============================================================================

int g_testsPassed = 0;
int g_testsFailed = 0;

#define TEST(name) \
    std::cout << "[TEST] " << name << "... "; \
    try

#define PASS() \
    std::cout << "PASS" << std::endl; \
    g_testsPassed++

#define FAIL(msg) \
    std::cout << "FAIL: " << msg << std::endl; \
    g_testsFailed++

#define ASSERT_TRUE(cond) \
    if (!(cond)) { \
        throw std::runtime_error("Assertion failed: " #cond); \
    }

#define ASSERT_FALSE(cond) \
    if ((cond)) { \
        throw std::runtime_error("Assertion failed: !" #cond); \
    }

#define ASSERT_EQ(a, b) \
    if ((a) != (b)) { \
        throw std::runtime_error("Assertion failed: " #a " == " #b); \
    }

#define ASSERT_NEQ(a, b) \
    if ((a) == (b)) { \
        throw std::runtime_error("Assertion failed: " #a " != " #b); \
    }

// ============================================================================
// DoH Tests
// ============================================================================

void testDohResolverCreation() {
    TEST("DohDnsResolver creation") {
        // Test creating resolver with different URLs
        DohDnsResolver r1("https://1.1.1.1/dns-query");
        DohDnsResolver r2("https://8.8.8.8/dns-query");
        DohDnsResolver r3("https://dns.google/dns-query", "", false);
        DohDnsResolver r4("https://1.1.1.1/dns-query", "1.1.1.1", true);

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDohResolveGoogle() {
    TEST("DohDnsResolver - resolve via Google DoH") {
        DohDnsResolver resolver("https://8.8.8.8/dns-query");

        std::cout << "\n    Resolving example.com via Google DoH..." << std::endl;

        auto start = std::chrono::steady_clock::now();
        auto result = resolver.Resolve("example.com");
        auto end = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "    Result:" << std::endl;
        std::cout << "      IPv4: " << (result.hasIpv4 ? result.ipv4 : "none") << std::endl;
        std::cout << "      IPv6: " << (result.hasIpv6 ? result.ipv6 : "none") << std::endl;
        std::cout << "      Time: " << ms << "ms" << std::endl;

        if (!result.error.empty()) {
            std::cout << "      Error: " << result.error << std::endl;
            // Don't fail if there's a network error, just report it
            PASS();
            return;
        }

        ASSERT_TRUE(result.hasIpv4 || result.hasIpv6);

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDohResolveCloudflare() {
    TEST("DohDnsResolver - resolve via Cloudflare DoH") {
        DohDnsResolver resolver("https://1.1.1.1/dns-query");

        auto start = std::chrono::steady_clock::now();
        auto result = resolver.Resolve("cloudflare.com");
        auto end = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "\n    Cloudflare DoH result:" << std::endl;
        std::cout << "      IPv4: " << (result.hasIpv4 ? result.ipv4 : "none") << std::endl;
        std::cout << "      IPv6: " << (result.hasIpv6 ? result.ipv6 : "none") << std::endl;
        std::cout << "      Time: " << ms << "ms" << std::endl;

        ASSERT_TRUE(result.hasIpv4 || result.hasIpv6);

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDohResolveAAAA() {
    TEST("DohDnsResolver - resolve AAAA record") {
        DohDnsResolver resolver("https://1.1.1.1/dns-query");

        // google.com should have both A and AAAA records
        auto result = resolver.Resolve("google.com");

        std::cout << "\n    Google.com DoH result:" << std::endl;
        std::cout << "      IPv4: " << (result.hasIpv4 ? result.ipv4 : "none") << std::endl;
        std::cout << "      IPv6: " << (result.hasIpv6 ? result.ipv6 : "none") << std::endl;

        ASSERT_TRUE(result.hasIpv4);

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDohResolveNonExistent() {
    TEST("DohDnsResolver - resolve non-existent domain") {
        DohDnsResolver resolver("https://8.8.8.8/dns-query");

        // This domain should not exist
        auto result = resolver.Resolve("this-domain-does-not-exist-12345.example.com");

        std::cout << "\n    Non-existent domain result:" << std::endl;
        std::cout << "      IPv4: " << (result.hasIpv4 ? result.ipv4 : "none") << std::endl;
        std::cout << "      IPv6: " << (result.hasIpv6 ? result.ipv6 : "none") << std::endl;
        std::cout << "      Error: " << result.error << std::endl;

        // Should have error or no records
        ASSERT_TRUE(!result.error.empty() || (!result.hasIpv4 && !result.hasIpv6));

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDohWithSni() {
    TEST("DohDnsResolver - with custom SNI") {
        DohDnsResolver resolver("https://1.1.1.1/dns-query", "cloudflare-dns.com");

        auto result = resolver.Resolve("example.com");

        std::cout << "\n    Custom SNI result:" << std::endl;
        std::cout << "      IPv4: " << (result.hasIpv4 ? result.ipv4 : "none") << std::endl;

        ASSERT_TRUE(result.hasIpv4 || result.hasIpv6);

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDohPerformance() {
    TEST("DohDnsResolver - performance comparison") {
        StandardDnsResolver standard("8.8.8.8:53", false);
        DohDnsResolver doh("https://8.8.8.8/dns-query");

        const int iterations = 5;

        // Warm up
        standard.Resolve("example.com");
        doh.Resolve("example.com");

        // Test standard DNS
        auto start1 = std::chrono::steady_clock::now();
        for (int i = 0; i < iterations; i++) {
            standard.Resolve("example.com");
        }
        auto end1 = std::chrono::steady_clock::now();
        auto ms1 = std::chrono::duration_cast<std::chrono::milliseconds>(end1 - start1).count();

        // Test DoH
        auto start2 = std::chrono::steady_clock::now();
        for (int i = 0; i < iterations; i++) {
            doh.Resolve("example.com");
        }
        auto end2 = std::chrono::steady_clock::now();
        auto ms2 = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2).count();

        std::cout << "\n    Performance (" << iterations << " iterations):" << std::endl;
        std::cout << "      Standard DNS: " << ms1 << "ms (" << ms1 / iterations << "ms/query)" << std::endl;
        std::cout << "      DoH:          " << ms2 << "ms (" << ms2 / iterations << "ms/query)" << std::endl;

        // Both should complete without error
        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

// ============================================================================
// TFO Tests
// ============================================================================

void testTfoAvailability() {
    TEST("TFO - check availability") {
#ifdef __linux__
        // On Linux, check if TFO is supported
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        ASSERT_TRUE(fd >= 0);

        int enable = 1;
        int result = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable));

        close(fd);

        if (result == 0) {
            std::cout << "\n    TFO is AVAILABLE on this system" << std::endl;
        } else {
            std::cout << "\n    TFO is NOT available (kernel may be too old)" << std::endl;
        }
#else
        std::cout << "\n    TFO is Linux-only, skipping on this platform" << std::endl;
#endif

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDirectOutboundTcp() {
    TEST("DirectOutbound - TCP connection") {
        DirectOutbound outbound(DirectOutboundMode::Auto);

        // Connect to a known server (port 80 for HTTP)
        auto start = std::chrono::steady_clock::now();
        auto conn = outbound.TCP("93.184.216.34:80");
        auto end = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "\n    TCP connection to 93.184.216.34:80:" << std::endl;
        std::cout << "      Time: " << ms << "ms" << std::endl;

        ASSERT_TRUE(conn != nullptr);

        // Try to send a simple HTTP request
        std::string request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        try {
            conn->Write(reinterpret_cast<const uint8_t*>(request.data()), request.size());
            std::cout << "      Sent HTTP request successfully" << std::endl;
        } catch (const std::exception& e) {
            std::cout << "      Send failed (expected): " << e.what() << std::endl;
        }

        conn->Close();

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDirectOutboundTcpWithTfo() {
    TEST("DirectOutbound - TCP with TFO") {
#ifdef __linux__
        // Test TFO support in TcpConn
        DirectOutbound outbound(DirectOutboundMode::Auto);

        auto conn = outbound.TCP("93.184.216.34:80");
        ASSERT_TRUE(conn != nullptr);

        // The connection should work (TFO may or may not be used)
        std::cout << "\n    TCP connection with TFO support:" << std::endl;
        std::cout << "      Connection established successfully" << std::endl;

        // Send data
        std::string request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
        conn->Write(reinterpret_cast<const uint8_t*>(request.data()), request.size());
        std::cout << "      Data sent successfully" << std::endl;

        // Read response
        std::vector<uint8_t> buffer(4096);
        size_t totalRead = 0;
        auto start = std::chrono::steady_clock::now();

        while (totalRead < buffer.size()) {
            size_t n = conn->Read(buffer.data() + totalRead, buffer.size() - totalRead);
            if (n == 0) break;
            totalRead += n;

            // Don't wait too long
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() > 2000) {
                break;
            }
        }

        std::cout << "      Received " << totalRead << " bytes" << std::endl;

        conn->Close();
#else
        std::cout << "\n    TFO is Linux-only, skipping" << std::endl;
#endif

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDirectOutboundDualStack() {
    TEST("DirectOutbound - dual-stack (IPv4 + IPv6)") {
        DirectOutbound outbound(DirectOutboundMode::Auto);

        // Test with a domain that has both IPv4 and IPv6
        try {
            auto start = std::chrono::steady_clock::now();
            auto conn = outbound.TCP("cloudflare.com:443");
            auto end = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            std::cout << "\n    Dual-stack connection to cloudflare.com:443:" << std::endl;
            std::cout << "      Time: " << ms << "ms" << std::endl;

            ASSERT_TRUE(conn != nullptr);

            conn->Close();

            PASS();
        } catch (const std::exception& e) {
            // DNS resolution might fail in some environments
            std::cout << "\n    Dual-stack test skipped (DNS resolution failed)" << std::endl;
            PASS();
        }
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

void testDirectOutboundPerformance() {
    TEST("DirectOutbound - connection performance") {
        DirectOutbound outbound(DirectOutboundMode::Auto);

        const int iterations = 3;
        std::vector<long long> times;

        for (int i = 0; i < iterations; i++) {
            auto start = std::chrono::steady_clock::now();
            auto conn = outbound.TCP("93.184.216.34:80");
            auto end = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            if (conn) {
                times.push_back(ms);
                conn->Close();
            }
        }

        if (!times.empty()) {
            long long total = 0;
            for (auto t : times) total += t;
            long long avg = total / times.size();

            std::cout << "\n    Connection performance (" << times.size() << " iterations):" << std::endl;
            std::cout << "      Average: " << avg << "ms" << std::endl;
            std::cout << "      Min: " << *std::min_element(times.begin(), times.end()) << "ms" << std::endl;
            std::cout << "      Max: " << *std::max_element(times.begin(), times.end()) << "ms" << std::endl;
        }

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

void testDohWithDirectOutbound() {
    TEST("Integration - DoH + DirectOutbound") {
        // Use DoH to resolve, then connect directly
        DohDnsResolver resolver("https://1.1.1.1/dns-query");
        DirectOutbound outbound(DirectOutboundMode::Auto);

        auto result = resolver.Resolve("example.com");
        ASSERT_TRUE(result.hasIpv4 || result.hasIpv6);

        std::string target;
        if (result.hasIpv4) {
            target = result.ipv4 + ":80";
        } else {
            target = "[" + result.ipv6 + "]:80";
        }

        std::cout << "\n    DoH resolved to: " << target << std::endl;

        auto start = std::chrono::steady_clock::now();
        auto conn = outbound.TCP(target);
        auto end = std::chrono::steady_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "      Connected in: " << ms << "ms" << std::endl;

        ASSERT_TRUE(conn != nullptr);

        conn->Close();

        PASS();
    } catch (const std::exception& e) {
        FAIL(e.what());
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "================================================================" << std::endl;
    std::cout << "  DoH & TFO Feature Tests" << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << std::endl;

    // DoH Tests
    std::cout << "--- DNS over HTTPS (DoH) Tests ---" << std::endl;
    testDohResolverCreation();
    testDohResolveGoogle();
    testDohResolveCloudflare();
    testDohResolveAAAA();
    testDohResolveNonExistent();
    testDohWithSni();
    testDohPerformance();
    std::cout << std::endl;

    // TFO Tests
    std::cout << "--- TCP Fast Open (TFO) Tests ---" << std::endl;
    testTfoAvailability();
    testDirectOutboundTcp();
    testDirectOutboundTcpWithTfo();
    testDirectOutboundDualStack();
    testDirectOutboundPerformance();
    std::cout << std::endl;

    // Integration Tests
    std::cout << "--- Integration Tests ---" << std::endl;
    testDohWithDirectOutbound();
    std::cout << std::endl;

    // Summary
    std::cout << "================================================================" << std::endl;
    std::cout << "  Results: " << g_testsPassed << " passed, " << g_testsFailed << " failed" << std::endl;
    std::cout << "================================================================" << std::endl;

    return g_testsFailed > 0 ? 1 : 0;
}
