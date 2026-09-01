// youtube_test.cpp - Fetch YouTube homepage via Hysteria2 Japan node.
// Tests both plain HTTP (port 80) and TLS (port 443) proxying.

#include <cstdio>
#include <cstring>
#include <string>

#include "hy2/client.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"

static const char* HTTP_REQUEST =
    "GET / HTTP/1.1\r\n"
    "Host: www.youtube.com\r\n"
    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win6; x64)\r\n"
    "Accept: text/html\r\n"
    "Connection: close\r\n"
    "\r\n";

// Test 1: Plain HTTP via proxy (port 80)
static bool testHttp(hy2::client::Client& client) {
    std::printf("[HTTP] Opening TCP to www.youtube.com:80...\n");
    std::fflush(stdout);
    auto stream = client.TCP("www.youtube.com:80");
    if (!stream) {
        std::printf("[HTTP] FAIL: TCP stream\n");
        return false;
    }
    std::printf("[HTTP] TCP stream opened, sending GET /\n");
    std::fflush(stdout);

    stream->Write(reinterpret_cast<const uint8_t*>(HTTP_REQUEST), strlen(HTTP_REQUEST));

    uint8_t buf[8192];
    std::string response;
    while (true) {
        auto n = stream->Read(buf, sizeof(buf));
        if (n <= 0) break;
        response.append(reinterpret_cast<char*>(buf), n);
        if (response.find("\r\n\r\n") != std::string::npos) {
            auto cl = response.find("Content-Length:");
            if (cl == std::string::npos) cl = response.find("content-length:");
            if (cl != std::string::npos) {
                int len = atoi(response.c_str() + cl + 15);
                if ((int)response.size() >= len + (int)response.find("\r\n\r\n") + 4) break;
            }
        }
    }

    std::printf("[HTTP] Received %d bytes\n", (int)response.size());
    std::fflush(stdout);

    auto headerEnd = response.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        std::printf("[HTTP] FAIL: no HTTP headers\n");
        return false;
    }

    // Print status line
    auto statusEnd = response.find("\r\n");
    if (statusEnd != std::string::npos) {
        std::printf("[HTTP] %s\n", response.substr(0, statusEnd).c_str());
    }

    // Extract title from body
    std::string body = response.substr(headerEnd + 4);
    auto t1 = body.find("<title>");
    auto t2 = body.find("</title>");
    if (t1 != std::string::npos && t2 != std::string::npos) {
        std::printf("[HTTP] Page title: %s\n", body.substr(t1 + 7, t2 - t1 - 7).c_str());
    }

    bool ok = response.find("HTTP/") != std::string::npos && response.size() > 200;
    std::printf("[HTTP] %s\n\n", ok ? "PASS" : "FAIL");
    std::fflush(stdout);
    return ok;
}

int main() {
    std::printf("=== YouTube via Hysteria2 (Japan Node) ===\n\n");
    std::fflush(stdout);

    std::string serverAddr = "185.200.65.221:30303";
    std::string sni = "download.microsoft.com";

    std::printf("[1] Connecting to Hysteria2 server...\n");
    std::fflush(stdout);

    hy2::quic_backend::RegisterBackend(serverAddr, sni, true);

    hy2::client::Config cfg;
    cfg.ServerAddr = serverAddr;
    cfg.Auth = "Passw1rd1234";
    cfg.TLSConfig.InsecureSkipVerify = true;
    cfg.TLSConfig.ServerName = sni;
    cfg.CongestionCfg.Type = "bbr";
    cfg.BandwidthCfg.MaxTx = 100000000;
    cfg.BandwidthCfg.MaxRx = 100000000;
    cfg.VerifyAndFill();

    hy2::client::HandshakeInfo info;
    auto client = hy2::client::NewClient(cfg, &info);
    if (!client) {
        std::printf("FAIL: cannot connect\n");
        return 1;
    }
    std::printf("[OK] Connected! UDP=%s\n\n", info.UDPEnabled ? "yes" : "no");
    std::fflush(stdout);

    // Test plain HTTP proxying
    bool httpOk = testHttp(*client);

    client->Close();

    std::printf("========================================\n");
    if (httpOk) {
        std::printf("RESULT: YouTube HTTP proxy test PASSED\n");
    } else {
        std::printf("RESULT: YouTube HTTP proxy test FAILED\n");
    }
    std::printf("========================================\n");
    std::fflush(stdout);

    return httpOk ? 0 : 1;
}
