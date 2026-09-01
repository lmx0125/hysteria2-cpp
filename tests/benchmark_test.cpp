// benchmark_test.cpp - Real-link throughput benchmark for HY2-C++.
// Requires HY2_WITH_QUIC_BACKEND=ON and a running Hysteria2 server.
//
// Usage: hy2_benchmark [server:port] [sni] [auth] [size_mb] [connections]
//   server:port  - Hysteria2 server address (default: from env HY2_SERVER)
//   sni          - TLS server name (default: download.microsoft.com)
//   auth         - Auth password (default: Passw1rd1234)
//   size_mb      - Download size in MB per connection (default: 100)
//   connections  - Number of parallel connections (default: 1)

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if __has_include(<openssl/ssl.h>)
#include <openssl/ssl.h>
#include <openssl/err.h>
#define HY2_BENCHMARK_OPENSSL 1
#else
#define HY2_BENCHMARK_OPENSSL 0
#endif

#include "hy2/client.hpp"
#if __has_include("hy2/quic_backend/quic_backend_factory.hpp")
#include "hy2/quic_backend/quic_backend_factory.hpp"
#define HY2_HAS_QUIC_BACKEND_FACTORY 1
#else
#define HY2_HAS_QUIC_BACKEND_FACTORY 0
#endif

// ---------------------------------------------------------------------------
// Helpers

static std::string envOrDefault(const char* name, const char* def) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string(def);
}

static double elapsedSec(std::chrono::steady_clock::time_point start) {
    auto now = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(now - start).count();
}

// ---------------------------------------------------------------------------
// Per-connection stats

struct ConnStats {
    uint64_t bytesReceived = 0;
    double durationSec = 0;
    double throughputMBs = 0;
    double throughputMbps = 0;
    bool success = false;
    std::string error;
};

// ---------------------------------------------------------------------------
// Download worker: connects to server, downloads sizeBytes via TCP, measures

ConnStats downloadWorker(const std::string& serverAddr, const std::string& sni,
                          const std::string& auth, uint64_t sizeBytes,
                          int connId) {
    ConnStats stats;

#if HY2_HAS_QUIC_BACKEND_FACTORY
    hy2::quic_backend::RegisterBackend(serverAddr, sni, true);
#endif

    hy2::client::Config cfg;
    cfg.ServerAddr = serverAddr;
    cfg.Auth = auth;
    cfg.TLSConfig.InsecureSkipVerify = true;
    cfg.TLSConfig.ServerName = sni;
    cfg.CongestionCfg.Type = "bbr";
    cfg.BandwidthCfg.MaxTx = 0; // unlimited
    cfg.BandwidthCfg.MaxRx = 0;
    cfg.VerifyAndFill();

    auto start = std::chrono::steady_clock::now();

    try {
        hy2::client::HandshakeInfo info;
        auto client = hy2::client::NewClient(cfg, &info);
        if (!client) {
            stats.error = "connect failed";
            return stats;
        }

        // Open a TCP stream to a test endpoint
        // Use port 80 (plain HTTP) since the QUIC proxy handles transport security
        auto stream = client->TCP("httpbin.org:80");
        if (!stream) {
            stats.error = "TCP open failed";
            client->Close();
            return stats;
        }

        // Send HTTP GET for a large response
        // Use /bytes/N endpoint which returns exactly N random bytes with
        // Content-Length header (unlike /stream/N which uses chunked encoding).
        std::string req = "GET /bytes/" + std::to_string(sizeBytes) +
                          " HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
        stream->Write(reinterpret_cast<const uint8_t*>(req.data()), req.size());

        // Read response - handle both Content-Length and chunked transfer encoding
        uint8_t buf[65536];
        uint64_t totalReceived = 0;
        bool headerPassed = false;
        std::string headerBuf;
        bool chunked = false;
        int64_t contentLength = -1;

        while (totalReceived < sizeBytes || contentLength <= 0) {
            size_t n = stream->Read(buf, sizeof(buf));
            if (n == 0) break; // EOF

            if (!headerPassed) {
                headerBuf.append(reinterpret_cast<char*>(buf), n);
                auto pos = headerBuf.find("\r\n\r\n");
                if (pos != std::string::npos) {
                    headerPassed = true;
                    // Parse headers for Transfer-Encoding and Content-Length
                    if (headerBuf.find("Transfer-Encoding: chunked") != std::string::npos ||
                        headerBuf.find("transfer-encoding: chunked") != std::string::npos) {
                        chunked = true;
                    }
                    auto clPos = headerBuf.find("Content-Length:");
                    if (clPos == std::string::npos) clPos = headerBuf.find("content-length:");
                    if (clPos != std::string::npos) {
                        contentLength = std::atoll(headerBuf.c_str() + clPos + 15);
                    }
                    // Count any body bytes already read with the headers
                    size_t bodyStart = pos + 4;
                    if (bodyStart < headerBuf.size()) {
                        totalReceived += headerBuf.size() - bodyStart;
                    }
                    if (contentLength > 0) {
                        // Debug: print first part of headers
                        std::string hdrs = headerBuf.substr(0, std::min<size_t>(pos, 300));
                        // (headers already printed by caller if needed)
                    }
                }
            } else if (chunked) {
                totalReceived += n;
            } else {
                totalReceived += n;
            }

            // Stop early if we have Content-Length and got it all
            if (contentLength > 0 && totalReceived >= static_cast<uint64_t>(contentLength)) break;
        }

        stats.bytesReceived = totalReceived;
        stats.success = totalReceived > 0;
        client->Close();
    } catch (const std::exception& e) {
        stats.error = e.what();
    } catch (...) {
        stats.error = "unknown exception";
    }

    stats.durationSec = elapsedSec(start);
    if (stats.durationSec > 0 && stats.bytesReceived > 0) {
        stats.throughputMBs = static_cast<double>(stats.bytesReceived) / (1024.0 * 1024.0) / stats.durationSec;
        stats.throughputMbps = stats.throughputMBs * 8.0;
    }

    return stats;
}

// ---------------------------------------------------------------------------
// Auto-analysis

static void analyzeResults(const ConnStats& stats, int numConns) {
    std::printf("\n");
    std::printf("==============================\n");
    std::printf("  AUTO ANALYSIS\n");
    std::printf("==============================\n\n");

    double totalMBs = stats.throughputMBs * numConns;

    if (!stats.success) {
        std::printf("[FAIL] Connection failed: %s\n", stats.error.c_str());
        return;
    }

    std::printf("Total Throughput: %.2f MB/s (%.1f Mbps)\n", totalMBs, totalMBs * 8.0);
    std::printf("Per Connection:   %.2f MB/s\n", stats.throughputMBs);
    std::printf("Duration:         %.1f seconds\n", stats.durationSec);
    std::printf("Data Received:    %.2f MB\n", stats.bytesReceived / (1024.0 * 1024.0));
    std::printf("\n");

    // Basic analysis based on throughput
    if (totalMBs < 1.0) {
        std::printf("[!] Throughput is very low (< 1 MB/s).\n");
        std::printf("    Possible causes:\n");
        std::printf("    - Network connectivity issue\n");
        std::printf("    - Server not responding\n");
        std::printf("    - TLS handshake failure\n");
        std::printf("    - QUIC connection failure\n");
    } else if (totalMBs < 10.0) {
        std::printf("[!] Throughput is low (< 10 MB/s).\n");
        std::printf("    Check:\n");
        std::printf("    - RTT (high RTT limits TCP throughput)\n");
        std::printf("    - Congestion window\n");
        std::printf("    - Server bandwidth limit\n");
    } else if (totalMBs < 50.0) {
        std::printf("[i] Throughput is moderate (< 50 MB/s).\n");
        std::printf("    Consider:\n");
        std::printf("    - Increasing connections\n");
        std::printf("    - Checking congestion control\n");
    } else {
        std::printf("[OK] Throughput is good (> 50 MB/s).\n");
    }

    std::printf("\n");
    std::printf("NOTE: For detailed QUIC/tx_queue analysis, use PrintStats()\n");
    std::printf("      on the Ngtcp2Connection objects during the transfer.\n");
}

// ---------------------------------------------------------------------------
// Main

#if !HY2_BENCHMARK_OPENSSL || !HY2_HAS_QUIC_BACKEND_FACTORY
int main() {
    std::printf("Benchmark requires OpenSSL and QUIC backend.\n");
    std::printf("Build with: cmake -DHY2_WITH_QUIC_BACKEND=ON\n");
    return 1;
}
#else

int main(int argc, char* argv[]) {
    std::printf("==============================================\n");
    std::printf("  HY2-C++ Performance Benchmark\n");
    std::printf("==============================================\n\n");

    // Parse args
    std::string serverAddr = (argc > 1) ? argv[1] : envOrDefault("HY2_SERVER", "");
    std::string sni = (argc > 2) ? argv[2] : envOrDefault("HY2_SNI", "download.microsoft.com");
    std::string auth = (argc > 3) ? argv[3] : envOrDefault("HY2_AUTH", "Passw1rd1234");
    int sizeMB = (argc > 4) ? std::atoi(argv[4]) : 100;
    int numConns = (argc > 5) ? std::atoi(argv[5]) : 1;

    if (serverAddr.empty()) {
        std::printf("Usage: hy2_benchmark [server:port] [sni] [auth] [size_mb] [connections]\n");
        std::printf("  Or set env: HY2_SERVER, HY2_SNI, HY2_AUTH\n");
        return 1;
    }

    uint64_t sizeBytes = static_cast<uint64_t>(sizeMB) * 1024 * 1024;

    std::printf("Configuration:\n");
    std::printf("  Server:     %s\n", serverAddr.c_str());
    std::printf("  SNI:        %s\n", sni.c_str());
    std::printf("  Auth:       %s\n", auth.c_str());
    std::printf("  Size/Conn:  %d MB\n", sizeMB);
    std::printf("  Conns:      %d\n", numConns);
    std::printf("\n");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    auto globalStart = std::chrono::steady_clock::now();

    // Launch connections
    std::vector<std::thread> threads;
    std::vector<ConnStats> results(numConns);
    std::mutex printMu;

    for (int i = 0; i < numConns; ++i) {
        threads.emplace_back([&, i] {
            auto stats = downloadWorker(serverAddr, sni, auth, sizeBytes, i);
            {
                std::lock_guard<std::mutex> lk(printMu);
                results[i] = stats;
                std::printf("[conn %d] %.2f MB/s (%.1f MB in %.1fs) %s\n",
                    i, stats.throughputMBs,
                    stats.bytesReceived / (1024.0 * 1024.0),
                    stats.durationSec,
                    stats.success ? "OK" : stats.error.c_str());
            }
        });
    }

    for (auto& t : threads) t.join();

    double totalDuration = elapsedSec(globalStart);

    // Aggregate
    uint64_t totalBytes = 0;
    double totalMBs = 0;
    int successCount = 0;
    for (auto& s : results) {
        totalBytes += s.bytesReceived;
        totalMBs += s.throughputMBs;
        if (s.success) successCount++;
    }

    // Output report
    std::printf("\n");
    std::printf("==============================\n");
    std::printf("  HY2-C++ PERFORMANCE REPORT\n");
    std::printf("==============================\n\n");

    std::printf("Duration:        %.1f seconds\n", totalDuration);
    std::printf("Connections:     %d / %d succeeded\n", successCount, numConns);
    std::printf("Bytes Received:  %.2f MB\n", totalBytes / (1024.0 * 1024.0));
    std::printf("Throughput:      %.2f MB/s (%.1f Mbps)\n", totalMBs, totalMBs * 8.0);
    std::printf("\n");

    std::printf("==============================\n");
    std::printf("  PER CONNECTION\n");
    std::printf("==============================\n\n");

    for (int i = 0; i < numConns; ++i) {
        auto& s = results[i];
        std::printf("  [%d] %.2f MB/s  %.1f MB  %.1fs  %s\n",
            i, s.throughputMBs,
            s.bytesReceived / (1024.0 * 1024.0),
            s.durationSec,
            s.success ? "OK" : s.error.c_str());
    }

    // Auto-analysis
    ConnStats aggStats;
    aggStats.bytesReceived = totalBytes;
    aggStats.durationSec = totalDuration;
    aggStats.throughputMBs = totalMBs / numConns;
    aggStats.success = successCount > 0;
    aggStats.throughputMbps = totalMBs * 8.0;
    analyzeResults(aggStats, numConns);

    return (successCount == numConns) ? 0 : 1;
}
#endif // HY2_BENCHMARK_OPENSSL
