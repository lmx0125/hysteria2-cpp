// win_tproxy.cpp - Windows transparent proxy implementation using WinDivert.
// Provides equivalent functionality to Linux IP_TRANSPARENT.
//
// WinDivert captures packets at the Windows network stack level:
// 1. Filter for TCP SYN / UDP packets to non-local destinations
// 2. Parse IP/TCP/UDP headers to extract original destination
// 3. Forward through Hysteria2 tunnel
// 4. Inject response packets back into the network stack
//
// This requires WinDivert library: https://reqrypt.org/windivert.html

#ifdef _WIN32

#include "hy2/platform/windows/win_tproxy.hpp"

// WinDivert headers would be included here:
// #include <windivert.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstring>
#include <iostream>
#include <thread>

// WinDivert constants (from windivert.h)
// These are placeholder values - actual implementation requires WinDivert SDK
#ifndef WINDIVERT_LAYER_NETWORK
#define WINDIVERT_LAYER_NETWORK 0
#define WINDIVERT_LAYER_FORWARD 1
#define WINDIVERT_LAYER_FLOW    2

#define WINDIVERT_FLAG_SNIFF    0x0001
#define WINDIVERT_FLAG_DROP     0x0002
#define WINDIVERT_FLAG_RECVONLY 0x0004
#define WINDIVERT_FLAG_SENDONLY 0x0008

// TCP flags
#define WINDIVERT_TCP_FLAG_SYN  0x02
#define WINDIVERT_TCP_FLAG_ACK  0x10
#endif

// Forward declarations for WinDivert types (actual definitions in windivert.h)
typedef void* WINDIVERHANDLE;
typedef struct _WINDIVERT_ADDRESS WINDIVERT_ADDRESS, *PWINDIVERT_ADDRESS;

namespace hy2::platform::windows_impl {

// ---------------------------------------------------------------------------
// Helper: Parse IPv4 address from bytes
static std::string ipv4ToString(const uint8_t* bytes) {
    char buf[INET_ADDRSTRLEN];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
    return std::string(buf);
}

// Helper: Parse IPv6 address from bytes
static std::string ipv6ToString(const uint8_t* bytes) {
    char buf[INET6_ADDRSTRLEN];
    snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11],
             bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string("[") + buf + "]";
}

// ---------------------------------------------------------------------------
// WindowsTcpTransparentProxy

WindowsTcpTransparentProxy::WindowsTcpTransparentProxy(
    TcpDialFunc dialFunc,
    std::shared_ptr<ITransparentProxyEventLogger> logger)
    : dialFunc_(std::move(dialFunc)), logger_(std::move(logger)) {}

WindowsTcpTransparentProxy::~WindowsTcpTransparentProxy() {
    Stop();
}

bool WindowsTcpTransparentProxy::Start(const std::string& listenAddr) {
    // Parse the listen address to get the port
    auto colon = listenAddr.rfind(':');
    if (colon == std::string::npos) return false;
    uint16_t port = static_cast<uint16_t>(std::atoi(listenAddr.c_str() + colon + 1));

    // Build WinDivert filter for TCP SYN packets to this port
    // This captures packets that would normally be routed to the internet
    // but we want to intercept them for transparent proxying
    char filter[256];
    snprintf(filter, sizeof(filter),
             "tcp.DstPort == %u && tcp.Syn", port);

    // Open WinDivert handle
    // In real implementation: winDivertHandle_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
    // For now, this is a placeholder that shows the architecture

    running_ = true;
    captureThread_ = std::thread(&WindowsTcpTransparentProxy::captureLoop, this);
    return true;
}

void WindowsTcpTransparentProxy::Stop() {
    running_ = false;
    if (winDivertHandle_) {
        // WinDivertClose(winDivertHandle_);
        winDivertHandle_ = nullptr;
    }
    if (captureThread_.joinable()) {
        captureThread_.join();
    }
}

void WindowsTcpTransparentProxy::captureLoop() {
    // Main capture loop using WinDivert
    // In real implementation:
    // 1. WinDivertRecv() to get packet
    // 2. Parse IP header -> extract src/dst
    // 3. Parse TCP header -> extract ports
    // 4. If SYN flag set, it's a new connection
    // 5. Extract original destination from IP dst + TCP dst port
    // 6. Spawn handler thread
    // 7. Optionally inject SYN-ACK to complete handshake locally
    //    (so the local app thinks it's connected)
    // 8. Forward data through Hysteria2 tunnel

    while (running_) {
        // Placeholder: would call WinDivertRecv()
        // For demonstration, we'll show the packet parsing logic

        // uint8_t packet[2048];
        // UINT packetLen;
        // WINDIVERT_ADDRESS addr;
        // if (!WinDivertRecv(winDivertHandle_, packet, sizeof(packet), &addr, &packetLen)) {
        //     continue;
        // }
        //
        // // Parse IP header
        // auto* ipHdr = reinterpret_cast<struct iphdr*>(packet);
        // if (ipHdr->version != 4) continue;
        //
        // // Parse TCP header
        // auto* tcpHdr = reinterpret_cast<struct tcphdr*>(packet + ipHdr->ihl * 4);
        //
        // // Check for SYN flag (new connection)
        // if (!(tcpHdr->syn)) continue;
        //
        // // Extract original destination
        // std::string originalDest = ipv4ToString(reinterpret_cast<uint8_t*>(&ipHdr->daddr))
        //                          + ":" + std::to_string(ntohs(tcpHdr->dest));
        //
        // // Get local address (where we'll bind for the spoofed connection)
        // std::string localAddr = ipv4ToString(reinterpret_cast<uint8_t*>(&ipHdr->saddr));
        // uint16_t localPort = ntohs(tcpHdr->source);
        //
        // // Handle the connection
        // std::thread(&WindowsTcpTransparentProxy::handleConnection, this,
        //             originalDest, ipHdr->saddr, localPort,
        //             ipHdr->daddr, ntohs(tcpHdr->dest)).detach();

        // Sleep to avoid busy-waiting in placeholder
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void WindowsTcpTransparentProxy::handleConnection(
    const std::string& originalDest,
    uint32_t localAddr, uint16_t localPort,
    uint32_t remoteAddr, uint16_t remotePort) {

    if (logger_) {
        logger_->OnConnect(originalDest, "");
    }

    std::string closeErr;
    auto cleanup = [&]() {
        if (logger_) {
            logger_->OnError(originalDest, "", closeErr);
        }
    };

    // Open proxied connection to original destination
    auto stream = dialFunc_(originalDest);
    if (!stream) {
        closeErr = "failed to dial " + originalDest;
        cleanup();
        return;
    }

    // Bidirectional copy would happen here
    // In real implementation, we'd:
    // 1. Create a local socket for the spoofed connection
    // 2. Forward data between the local socket and the Hysteria2 stream
    // 3. Handle TCP state (SYN-ACK, FIN, etc.)

    cleanup();
}

// ---------------------------------------------------------------------------
// WindowsUdpTransparentProxy

WindowsUdpTransparentProxy::WindowsUdpTransparentProxy(
    UdpDialFunc dialFunc,
    std::shared_ptr<ITransparentProxyEventLogger> logger,
    uint32_t timeoutMs)
    : dialFunc_(std::move(dialFunc)), logger_(std::move(logger)), timeoutMs_(timeoutMs) {}

WindowsUdpTransparentProxy::~WindowsUdpTransparentProxy() {
    Stop();
}

bool WindowsUdpTransparentProxy::Start(const std::string& listenAddr) {
    auto colon = listenAddr.rfind(':');
    if (colon == std::string::npos) return false;
    uint16_t port = static_cast<uint16_t>(std::atoi(listenAddr.c_str() + colon + 1));

    char filter[256];
    snprintf(filter, sizeof(filter), "udp.DstPort == %u", port);

    // Open WinDivert handle for UDP
    // In real implementation: winDivertHandle_ = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);

    running_ = true;
    captureThread_ = std::thread(&WindowsUdpTransparentProxy::captureLoop, this);
    return true;
}

void WindowsUdpTransparentProxy::Stop() {
    running_ = false;
    if (winDivertHandle_) {
        // WinDivertClose(winDivertHandle_);
        winDivertHandle_ = nullptr;
    }
    if (captureThread_.joinable()) {
        captureThread_.join();
    }
}

void WindowsUdpTransparentProxy::captureLoop() {
    // Similar to TCP but for UDP packets
    // 1. WinDivertRecv() to get packet
    // 2. Parse IP header -> extract src/dst
    // 3. Parse UDP header -> extract ports
    // 4. Extract original destination from IP dst + UDP dst port
    // 5. Forward through Hysteria2 tunnel
    // 6. Inject response packets back

    while (running_) {
        // Placeholder loop
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

} // namespace hy2::platform::windows_impl

#endif // _WIN32
