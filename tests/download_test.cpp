// download_test.cpp - Download a large file via Hysteria2 QUIC proxy and verify SHA256 hash.
//
// Usage:
//   hy2_download_test [server_addr] [auth]
//   hy2_download_test 185.200.65.221:30303 Passw1rd1234

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include <openssl/evp.h>

#include "hy2/client.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

static const char* DOWNLOAD_HOST = "media.inkscape.org";
static const char* DOWNLOAD_PATH =
    "/dl/resources/file/inkscape-1.4.4_2026-05-05_dcaf3e7-x64.signed.exe";
static const char* DOWNLOAD_ADDR = "media.inkscape.org:80";

// Known SHA256 hash of inkscape-1.4.4_2026-05-05_dcaf3e7-x64.signed.exe
static const char* EXPECTED_SHA256 = "fa21d25e56dbfe41e9b014a4f37689edda4bb41d5a3597fe2787dff6c10e651f";

struct DownloadResult {
    uint64_t bytes = 0;
    double elapsed_sec = 0.0;
    double speed_mbps = 0.0;
    unsigned char sha256[32];
    bool ok = false;
    std::string error;
};

static void sha256_to_hex(const unsigned char hash[32], char hex[65]) {
    for (int i = 0; i < 32; ++i)
        std::sprintf(hex + i * 2, "%02x", hash[i]);
    hex[64] = '\0';
}

static DownloadResult downloadViaProxy(
    const std::string& serverAddr, const std::string& auth) {

    DownloadResult result;
    auto t0 = std::chrono::steady_clock::now();

    // Register QUIC backend
    hy2::quic_backend::RegisterBackend(serverAddr, serverAddr, true);

    // Create client config
    hy2::client::Config cfg;
    cfg.ServerAddr = serverAddr;
    cfg.Auth = auth;
    cfg.TLSConfig.InsecureSkipVerify = true;
    cfg.TLSConfig.ServerName = "download.microsoft.com";
    cfg.CongestionCfg.Type = "bbr";
    cfg.BandwidthCfg.MaxTx = 100000000;
    cfg.BandwidthCfg.MaxRx = 100000000;
    cfg.VerifyAndFill();

    // Connect with retries
    std::printf("  [1/4] Connecting to %s...\n", serverAddr.c_str());
    std::fflush(stdout);
    hy2::client::HandshakeInfo info;
    std::shared_ptr<hy2::client::Client> client;
    for (int attempt = 1; attempt <= 3; ++attempt) {
        try {
            client = hy2::client::NewClient(cfg, &info);
            break;
        } catch (const std::exception& e) {
            std::printf("  [1/4] Attempt %d failed: %s\n", attempt, e.what());
            std::fflush(stdout);
            if (attempt < 3) {
                std::printf("  [1/4] Retrying in 2s...\n");
                std::fflush(stdout);
                std::this_thread::sleep_for(std::chrono::seconds(2));
            } else {
                result.error = std::string("connect failed after 3 attempts: ") + e.what();
                return result;
            }
        }
    }
    if (!client) {
        result.error = "client is null";
        return result;
    }
    std::printf("  [1/4] Connected! UDP=%s\n", info.UDPEnabled ? "yes" : "no");
    std::fflush(stdout);

    // Open TCP stream
    std::printf("  [2/4] Opening TCP to %s...\n", DOWNLOAD_ADDR);
    std::fflush(stdout);
    std::shared_ptr<hy2::IByteReaderWriter> stream;
    try {
        stream = client->TCP(DOWNLOAD_ADDR);
    } catch (const std::exception& e) {
        result.error = std::string("TCP open failed: ") + e.what();
        client->Close();
        return result;
    }
    if (!stream) {
        result.error = "TCP stream is null";
        client->Close();
        return result;
    }
    std::printf("  [2/4] TCP stream opened\n");
    std::fflush(stdout);

    // Send HTTP/1.1 GET request
    std::printf("  [3/4] Sending HTTP GET %s...\n", DOWNLOAD_PATH);
    std::fflush(stdout);
    std::string httpReq =
        "GET " + std::string(DOWNLOAD_PATH) + " HTTP/1.1\r\n"
        "Host: " + std::string(DOWNLOAD_HOST) + "\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "\r\n";
    try {
        stream->Write(reinterpret_cast<const uint8_t*>(httpReq.data()), httpReq.size());
    } catch (const std::exception& e) {
        result.error = std::string("write failed: ") + e.what();
        client->Close();
        return result;
    }

    // Read response using large buffer
    std::printf("  [3/4] Reading response...\n");
    std::fflush(stdout);
    std::string headerBuf;
    bool headerComplete = false;
    int headerStatus = 0;
    uint8_t rbuf[65536];
    for (int round = 0; round < 1000 && !headerComplete; ++round) {
        auto n = stream->Read(rbuf, sizeof(rbuf));
        if (n <= 0) break;
        headerBuf.append(reinterpret_cast<char*>(rbuf), n);
        // Search for end-of-headers marker
        auto pos = headerBuf.find("\r\n\r\n");
        if (pos != std::string::npos) {
            headerComplete = true;
            // Parse status code from "HTTP/1.1 200 OK"
            if (headerBuf.size() >= 12)
                headerStatus = std::atoi(headerBuf.c_str() + 9);
        }
    }

    if (!headerComplete) {
        result.error = "incomplete HTTP headers";
        client->Close();
        return result;
    }

    // Check for Content-Length and Transfer-Encoding
    bool chunked = false;
    long long contentLength = -1;
    if (headerBuf.find("Transfer-Encoding: chunked") != std::string::npos ||
        headerBuf.find("transfer-encoding: chunked") != std::string::npos ||
        headerBuf.find("Transfer-Encoding: Chunked") != std::string::npos) {
        chunked = true;
    }
    // Parse Content-Length
    {
        auto clPos = headerBuf.find("Content-Length:");
        if (clPos == std::string::npos) clPos = headerBuf.find("content-length:");
        if (clPos != std::string::npos) {
            contentLength = std::atoll(headerBuf.c_str() + clPos + 15);
        }
    }

    std::printf("  [3/4] HTTP %d, chunked=%s, content-length=%lld, downloading...\n",
                headerStatus, chunked ? "yes" : "no", contentLength);
    std::fflush(stdout);

    if (headerStatus != 200) {
        result.error = "HTTP status " + std::to_string(headerStatus);
        // Print first part of response for debugging
        if (headerBuf.size() > 500) headerBuf.resize(500);
        std::printf("  [DEBUG] Response headers:\n%s\n", headerBuf.c_str());
        client->Close();
        return result;
    }

    // Compute SHA256 while reading body
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);

    uint8_t buf[65536];
    uint64_t totalBytes = 0;
    auto tStart = std::chrono::steady_clock::now();

    // First, feed any body bytes that were read along with headers
    {
        auto bodyStart = headerBuf.find("\r\n\r\n") + 4;
        if (bodyStart < headerBuf.size()) {
            size_t bodyInHeader = headerBuf.size() - bodyStart;
            EVP_DigestUpdate(mdctx, headerBuf.data() + bodyStart, bodyInHeader);
            totalBytes += bodyInHeader;
        }
    }

    if (chunked) {
        // Read chunked transfer encoding
        for (;;) {
            // Read chunk size line
            std::string chunkSizeLine;
            for (;;) {
                uint8_t ch;
                auto n = stream->Read(&ch, 1);
                if (n <= 0) goto done_chunked;
                chunkSizeLine.push_back(static_cast<char>(ch));
                if (chunkSizeLine.size() >= 2 &&
                    chunkSizeLine[chunkSizeLine.size()-2]=='\r' &&
                    chunkSizeLine[chunkSizeLine.size()-1]=='\n') {
                    break;
                }
            }
            // Parse hex chunk size
            unsigned long chunkSize = std::strtoul(chunkSizeLine.c_str(), nullptr, 16);
            if (chunkSize == 0) break; // final chunk

            // Read chunk data
            uint64_t remaining = chunkSize;
            while (remaining > 0) {
                size_t toRead = remaining < sizeof(buf) ? remaining : sizeof(buf);
                auto n = stream->Read(buf, toRead);
                if (n <= 0) goto done_chunked;
                EVP_DigestUpdate(mdctx, buf, n);
                totalBytes += n;
                remaining -= n;
            }
            // Read trailing \r\n
            uint8_t crlf[2];
            stream->Read(crlf, 2);
        }
        done_chunked:;
    } else if (contentLength > 0) {
        // Use Content-Length to know exactly when to stop
        uint64_t remaining = static_cast<uint64_t>(contentLength);
        while (remaining > 0) {
            size_t toRead = remaining < sizeof(buf) ? remaining : sizeof(buf);
            auto n = stream->Read(buf, toRead);
            if (n <= 0) break;
            EVP_DigestUpdate(mdctx, buf, n);
            totalBytes += n;
            remaining -= n;
        }
    } else {
        // Read until EOF
        for (;;) {
            auto n = stream->Read(buf, sizeof(buf));
            if (n <= 0) break;
            EVP_DigestUpdate(mdctx, buf, n);
            totalBytes += n;
        }
    }

    auto tEnd = std::chrono::steady_clock::now();
    result.elapsed_sec = std::chrono::duration<double>(tEnd - tStart).count();
    result.bytes = totalBytes;

    if (result.elapsed_sec > 0.0) {
        result.speed_mbps = (double)totalBytes / result.elapsed_sec / (1024.0 * 1024.0);
    }

    // Finalize hash
    unsigned int hashLen = 0;
    EVP_DigestFinal_ex(mdctx, result.sha256, &hashLen);
    EVP_MD_CTX_free(mdctx);

    result.ok = true;
    client->Close();
    return result;
}

int main(int argc, char* argv[]) {
    std::printf("=== Hysteria2 QUIC Download Test ===\n");
    std::printf("URL: https://%s%s\n", DOWNLOAD_HOST, DOWNLOAD_PATH);
    std::fflush(stdout);

    // Node configs
    struct Node { const char* name; const char* addr; const char* auth; };
    Node nodes[] = {
        {"Japan",  "185.200.65.221:30303", "Passw1rd1234"},
        {"Canada", "149.5.247.123:30303",  "Passw1rd1234"},
    };

    int selectedNode = 0;
    std::string serverAddr, auth;
    if (argc >= 3) {
        serverAddr = argv[1];
        auth = argv[2];
        std::printf("Using custom server: %s\n", serverAddr.c_str());
    } else {
        std::printf("Nodes: 0=Japan, 1=Canada [default=0]\n");
        std::printf("Select node (0/1): ");
        std::fflush(stdout);
        char ch = '0';
        std::scanf(" %c", &ch);
        selectedNode = (ch == '1') ? 1 : 0;
        serverAddr = nodes[selectedNode].addr;
        auth = nodes[selectedNode].auth;
    }

    std::printf("\nConnecting to %s node (%s)...\n\n",
                nodes[selectedNode].name, serverAddr.c_str());
    std::fflush(stdout);

    auto result = downloadViaProxy(serverAddr, auth);

    std::printf("\n");
    std::printf("========================================\n");
    if (!result.ok) {
        std::printf("RESULT: FAIL - %s\n", result.error.c_str());
    } else {
        char hex[65];
        sha256_to_hex(result.sha256, hex);
        std::printf("RESULT: SUCCESS\n");
        std::printf("  Downloaded: %.2f MB (%llu bytes)\n",
                    result.bytes / (1024.0 * 1024.0),
                    (unsigned long long)result.bytes);
        std::printf("  Time:       %.2f seconds\n", result.elapsed_sec);
        std::printf("  Speed:      %.2f MB/s\n", result.speed_mbps);
        std::printf("  SHA256:     %s\n", hex);
        if (EXPECTED_SHA256) {
            if (std::strcmp(hex, EXPECTED_SHA256) == 0) {
                std::printf("  Hash check: PASS\n");
            } else {
                std::printf("  Hash check: FAIL (expected %s)\n", EXPECTED_SHA256);
            }
        } else {
            std::printf("  Hash check: (no expected hash set, verify manually)\n");
        }
    }
    std::printf("========================================\n");
    std::fflush(stdout);

    return result.ok ? 0 : 1;
}
