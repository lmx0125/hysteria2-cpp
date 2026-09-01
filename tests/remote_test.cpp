// remote_test.cpp - Test C++ client against remote Hysteria2 servers.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "hy2/client.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

static const char* HTTP_REQUEST =
    "GET /ip HTTP/1.1\r\n"
    "Host: httpbin.org\r\n"
    "Connection: close\r\n"
    "\r\n";

struct NodeConfig {
    const char* name;
    const char* serverAddr;
    const char* password;
    const char* sni;
};

void testNode(const NodeConfig& node) {
    std::printf("========================================\n");
    std::printf("Testing: %s\n", node.name);
    std::printf("Server:  %s\n", node.serverAddr);
    std::printf("SNI:     %s\n", node.sni);
    std::printf("========================================\n");
    std::fflush(stdout);

    // Create config
    hy2::client::Config cfg;
    cfg.ServerAddr = node.serverAddr;
    cfg.Auth = node.password;
    cfg.TLSConfig.InsecureSkipVerify = true;
    cfg.TLSConfig.ServerName = node.sni;
    cfg.CongestionCfg.Type = "bbr";
    cfg.BandwidthCfg.MaxTx = 100000000;
    cfg.BandwidthCfg.MaxRx = 100000000;
    cfg.VerifyAndFill();

    // Register QUIC backend
    std::printf("[STEP1] Registering QUIC backend...\n");
    std::fflush(stdout);
    hy2::quic_backend::RegisterBackend(node.serverAddr, node.sni, true);
    std::printf("[STEP1] Done\n");
    std::fflush(stdout);

    // Connect
    std::printf("[STEP2] Connecting...\n");
    std::fflush(stdout);
    hy2::client::HandshakeInfo info;
    std::shared_ptr<hy2::client::Client> client;
    try {
        client = hy2::client::NewClient(cfg, &info);
    } catch (const std::exception& e) {
        std::printf("[STEP2] FAIL: %s\n", e.what());
        std::fflush(stdout);
        return;
    }
    if (!client) {
        std::printf("[STEP2] FAIL: client is null\n");
        std::fflush(stdout);
        return;
    }
    std::printf("[STEP2] Connected! UDP=%s\n", info.UDPEnabled ? "yes" : "no");
    std::fflush(stdout);

    // TCP test
    std::printf("[STEP3] TCP proxy to httpbin.org:80...\n");
    std::fflush(stdout);
    try {
        auto stream = client->TCP("httpbin.org:80");
        if (!stream) {
            std::printf("[STEP3] FAIL: stream is null\n");
        } else {
            stream->Write(reinterpret_cast<const uint8_t*>(HTTP_REQUEST), strlen(HTTP_REQUEST));
            std::printf("[STEP3] Request sent, reading response...\n");
            std::fflush(stdout);

            uint8_t buf[4096];
            std::string response;
            while (true) {
                auto n = stream->Read(buf, sizeof(buf));
                if (n <= 0) break;
                response.append(reinterpret_cast<char*>(buf), n);
            }
            std::printf("[STEP3] Received %d bytes\n", (int)response.size());
            if (response.find("HTTP/") != std::string::npos) {
                // Extract status line
                auto statusEnd = response.find("\r\n");
                if (statusEnd != std::string::npos) {
                    std::printf("[STEP3] %s\n", response.substr(0, statusEnd).c_str());
                }
                // Extract body (after \r\n\r\n)
                auto bodyStart = response.find("\r\n\r\n");
                if (bodyStart != std::string::npos) {
                    std::string body = response.substr(bodyStart + 4);
                    if (body.size() > 200) body.resize(200);
                    std::printf("[DATA] %s\n", body.c_str());
                }
            } else {
                std::printf("[WARN] Not HTTP response\n");
            }
            std::fflush(stdout);
        }
    } catch (const std::exception& e) {
        std::printf("[STEP3] Exception: %s\n", e.what());
        std::fflush(stdout);
    }

    // Cleanup
    client->Close();
    std::printf("[DONE] %s test complete\n\n", node.name);
    std::fflush(stdout);
}

int main() {
    std::printf("=== Hysteria2 Remote Node Test ===\n\n");

    NodeConfig nodes[] = {
        {"LXC-CA1 (Canada)", "149.5.247.123:30303", "Passw1rd1234", "download.microsoft.com"},
        {"NAR-JP (Japan)",   "185.200.65.221:30303", "Passw1rd1234", "download.microsoft.com"},
    };

    for (auto& node : nodes) {
        testNode(node);
    }

    std::printf("All tests complete.\n");
    return 0;
}
