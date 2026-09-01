// interop_test.cpp - Test C++ client against official Hysteria2 server.

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "hy2/client.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

static const char* HTTP_REQUEST =
    "GET / HTTP/1.1\r\n"
    "Host: httpbin.org\r\n"
    "Connection: close\r\n"
    "\r\n";

int main(int argc, char* argv[]) {
    std::printf("=== Hysteria2 C++ Client Interop Test ===\n");
    std::fflush(stdout);

    std::string serverAddr = "127.0.0.1:36714";
    std::string auth = "testpass123";
    if (argc >= 2) serverAddr = argv[1];
    if (argc >= 3) auth = argv[2];

    std::printf("Server: %s\n", serverAddr.c_str());
    std::printf("Auth:   %s\n", auth.c_str());
    std::fflush(stdout);

    // Step 1: Register QUIC backend
    std::printf("[STEP1] Registering QUIC backend...\n");
    std::fflush(stdout);
    hy2::quic_backend::RegisterBackend(serverAddr, serverAddr, true);
    std::printf("[STEP1] Done\n");
    std::fflush(stdout);

    // Step 2: Create client config
    std::printf("[STEP2] Creating client config...\n");
    std::fflush(stdout);
    hy2::client::Config cfg;
    cfg.ServerAddr = serverAddr;
    std::printf("[STEP2a] ServerAddr set\n"); std::fflush(stdout);
    cfg.Auth = auth;
    std::printf("[STEP2b] Auth set\n"); std::fflush(stdout);
    cfg.TLSConfig.InsecureSkipVerify = true;
    std::printf("[STEP2c] TLS set\n"); std::fflush(stdout);
    cfg.CongestionCfg.Type = "bbr";
    std::printf("[STEP2d] CC set\n"); std::fflush(stdout);
    cfg.BandwidthCfg.MaxTx = 100000000;
    cfg.BandwidthCfg.MaxRx = 100000000;
    std::printf("[STEP2e] BW set, calling VerifyAndFill...\n"); std::fflush(stdout);
    cfg.VerifyAndFill();
    std::printf("[STEP2] Done\n");
    std::fflush(stdout);

    // Step 3: Connect to server
    std::printf("[STEP3] Connecting to server...\n");
    std::fflush(stdout);
    hy2::client::HandshakeInfo info;
    std::shared_ptr<hy2::client::Client> client;
    try {
        client = hy2::client::NewClient(cfg, &info);
    } catch (const std::exception& e) {
        std::printf("[STEP3] Exception: %s\n", e.what());
        std::fflush(stdout);
        return 1;
    }
    if (!client) {
        std::printf("[STEP3] Failed: client is null\n");
        std::fflush(stdout);
        return 1;
    }
    std::printf("[STEP3] Connected! UDP=%s ECH=%s\n",
                info.UDPEnabled ? "yes" : "no",
                info.ECHAccepted ? "yes" : "no");
    std::fflush(stdout);

    // Step 4: TCP proxy test
    std::printf("[STEP4] Opening TCP stream to httpbin.org:80...\n");
    std::fflush(stdout);
    try {
        auto stream = client->TCP("httpbin.org:80");
        if (!stream) {
            std::printf("[STEP4] Failed to open TCP stream\n");
        } else {
            std::printf("[STEP4] Stream opened, sending HTTP request...\n");
            std::fflush(stdout);
            stream->Write(reinterpret_cast<const uint8_t*>(HTTP_REQUEST), strlen(HTTP_REQUEST));
            std::printf("[STEP4] Request sent, reading response...\n");
            std::fflush(stdout);

            uint8_t buf[4096];
            std::string response;
            while (true) {
                auto n = stream->Read(buf, sizeof(buf));
                if (n <= 0) break;
                response.append(reinterpret_cast<char*>(buf), n);
            }
            std::printf("[STEP4] Received %d bytes\n", (int)response.size());
            if (response.find("HTTP/") != std::string::npos) {
                std::printf("[STEP4] Valid HTTP response!\n");
                if (response.size() > 300) response.resize(300);
                std::printf("[DATA] %s\n", response.c_str());
            }
            std::fflush(stdout);
        }
    } catch (const std::exception& e) {
        std::printf("[STEP4] Exception: %s\n", e.what());
        std::fflush(stdout);
    }

    // Step 5: Cleanup
    std::printf("[STEP5] Closing client...\n");
    std::fflush(stdout);
    client->Close();
    std::printf("[STEP5] Done\n");
    std::fflush(stdout);

    return 0;
}
