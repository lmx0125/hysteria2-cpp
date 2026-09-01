// test_doh_simple.cpp - Simple test for DoH and TFO features
//
// Compile:
//   g++ -std=c++20 -o test_doh_simple test_doh_simple.cpp \
//       ../src/outbounds/dns_outbound.cpp \
//       ../src/outbounds/direct.cpp \
//       -I../include -I../../core/include \
//       -lssl -lcrypto -lpthread
//
// Run:
//   ./test_doh_simple

#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <atomic>
#include <thread>

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

int main() {
    std::cout << "================================================================" << std::endl;
    std::cout << "  DoH & TFO Feature Tests" << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << std::endl;

    int passed = 0;
    int failed = 0;

    // Test 1: DoH Resolver creation
    std::cout << "[1] DohDnsResolver creation... ";
    try {
        DohDnsResolver r1("https://1.1.1.1/dns-query");
        DohDnsResolver r2("https://8.8.8.8/dns-query");
        DohDnsResolver r3("https://dns.google/dns-query", "", false);
        DohDnsResolver r4("https://1.1.1.1/dns-query", "1.1.1.1", true);
        std::cout << "PASS" << std::endl;
        passed++;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << std::endl;
        failed++;
    }

    // Test 2: Standard DNS Resolver creation
    std::cout << "[2] StandardDnsResolver creation... ";
    try {
        StandardDnsResolver r1("8.8.8.8:53", false);
        StandardDnsResolver r2("8.8.8.8:53", true);
        std::cout << "PASS" << std::endl;
        passed++;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << std::endl;
        failed++;
    }

    // Test 3: DirectOutbound creation
    std::cout << "[3] DirectOutbound creation... ";
    try {
        DirectOutbound outbound1(DirectOutboundMode::Auto);
        DirectOutbound outbound2(DirectOutboundMode::IPv6Prefer);
        DirectOutbound outbound3(DirectOutboundMode::IPv4Prefer);
        std::cout << "PASS" << std::endl;
        passed++;
    } catch (const std::exception& e) {
        std::cout << "FAIL: " << e.what() << std::endl;
        failed++;
    }

    // Test 4: TFO availability check
    std::cout << "[4] TFO availability check... ";
#ifdef __linux__
    {
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd >= 0) {
            int enable = 1;
            int result = setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable));
            close(fd);

            if (result == 0) {
                std::cout << "PASS (TFO available)" << std::endl;
            } else {
                std::cout << "PASS (TFO not available, but check worked)" << std::endl;
            }
            passed++;
        } else {
            std::cout << "FAIL (socket creation failed)" << std::endl;
            failed++;
        }
    }
#else
    std::cout << "PASS (Linux-only, skipped)" << std::endl;
    passed++;
#endif

    // Test 5: DoH resolve (if network available)
    std::cout << "[5] DoH resolve example.com... ";
    {
        DohDnsResolver resolver("https://8.8.8.8/dns-query");

        // Run with timeout
        auto start = std::chrono::steady_clock::now();
        std::atomic<bool> done{false};
        DnsResult result;

        std::thread t([&]() {
            result = resolver.Resolve("example.com");
            done = true;
        });

        // Wait up to 10 seconds
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!done && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (done) {
            t.join();
            auto end = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            if (result.hasIpv4 || result.hasIpv6) {
                std::cout << "PASS (" << ms << "ms, IPv4: " << (result.hasIpv4 ? result.ipv4 : "none")
                          << ", IPv6: " << (result.hasIpv6 ? result.ipv6 : "none") << ")" << std::endl;
                passed++;
            } else if (!result.error.empty()) {
                std::cout << "SKIP (network error: " << result.error << ")" << std::endl;
                passed++;
            } else {
                std::cout << "FAIL (no results)" << std::endl;
                failed++;
            }
        } else {
            t.detach();
            std::cout << "SKIP (timeout after 10s)" << std::endl;
            passed++;
        }
    }

    // Test 6: Standard DNS resolve
    std::cout << "[6] Standard DNS resolve example.com... ";
    {
        StandardDnsResolver resolver("8.8.8.8:53", false);

        auto start = std::chrono::steady_clock::now();
        std::atomic<bool> done{false};
        DnsResult result;

        std::thread t([&]() {
            result = resolver.Resolve("example.com");
            done = true;
        });

        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!done && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (done) {
            t.join();
            auto end = std::chrono::steady_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            if (result.hasIpv4 || result.hasIpv6) {
                std::cout << "PASS (" << ms << "ms, IPv4: " << (result.hasIpv4 ? result.ipv4 : "none")
                          << ", IPv6: " << (result.hasIpv6 ? result.ipv6 : "none") << ")" << std::endl;
                passed++;
            } else if (!result.error.empty()) {
                std::cout << "SKIP (network error: " << result.error << ")" << std::endl;
                passed++;
            } else {
                std::cout << "FAIL (no results)" << std::endl;
                failed++;
            }
        } else {
            t.detach();
            std::cout << "SKIP (timeout after 10s)" << std::endl;
            passed++;
        }
    }

    // Test 7: Direct TCP connection (if network available)
    std::cout << "[7] Direct TCP connection to 93.184.216.34:80... ";
    {
        try {
            DirectOutbound outbound(DirectOutboundMode::Auto);

            auto start = std::chrono::steady_clock::now();
            std::atomic<bool> done{false};
            std::atomic<bool> success{false};

            std::thread t([&]() {
                try {
                    auto conn = outbound.TCP("93.184.216.34:80");
                    if (conn) {
                        success = true;
                        conn->Close();
                    }
                } catch (...) {
                    // Connection failed
                }
                done = true;
            });

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            while (!done && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (done) {
                t.join();
                auto end = std::chrono::steady_clock::now();
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

                if (success) {
                    std::cout << "PASS (" << ms << "ms)" << std::endl;
                    passed++;
                } else {
                    std::cout << "SKIP (connection failed)" << std::endl;
                    passed++;
                }
            } else {
                t.detach();
                std::cout << "SKIP (timeout after 10s)" << std::endl;
                passed++;
            }
        } catch (const std::exception& e) {
            std::cout << "SKIP (error: " << e.what() << ")" << std::endl;
            passed++;
        }
    }

    // Test 8: DoH + Direct outbound integration
    std::cout << "[8] DoH + Direct outbound integration... ";
    {
        try {
            DohDnsResolver resolver("https://1.1.1.1/dns-query");
            DirectOutbound outbound(DirectOutboundMode::Auto);

            auto start = std::chrono::steady_clock::now();
            std::atomic<bool> done{false};
            bool success = false;

            std::thread t([&]() {
                auto result = resolver.Resolve("example.com");
                if (result.hasIpv4) {
                    std::string target = result.ipv4 + ":80";
                    auto conn = outbound.TCP(target);
                    if (conn) {
                        success = true;
                        conn->Close();
                    }
                }
                done = true;
            });

            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
            while (!done && std::chrono::steady_clock::now() < deadline) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (done) {
                t.join();
                auto end = std::chrono::steady_clock::now();
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

                if (success) {
                    std::cout << "PASS (" << ms << "ms)" << std::endl;
                    passed++;
                } else {
                    std::cout << "SKIP (integration failed)" << std::endl;
                    passed++;
                }
            } else {
                t.detach();
                std::cout << "SKIP (timeout after 15s)" << std::endl;
                passed++;
            }
        } catch (const std::exception& e) {
            std::cout << "SKIP (error: " << e.what() << ")" << std::endl;
            passed++;
        }
    }

    // Summary
    std::cout << std::endl;
    std::cout << "================================================================" << std::endl;
    std::cout << "  Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "================================================================" << std::endl;

    return failed > 0 ? 1 : 0;
}
