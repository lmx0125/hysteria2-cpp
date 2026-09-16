// hy_server_session.hpp - Real-QUIC server session implementing the
// Hysteria2 application protocol on top of Ngtcp2Listener:
//
//   Official Client ──HTTP/3 POST /auth──▶ hy2-cpp Server (this file)
//        ◀──────────── 233 + headers ──────┘
//        ──stream: TCPRequest(0x401)────▶ dial via Outbound, relay
//        ──datagram: UDPMessage─────────▶ Outbound UDP, replies back
#pragma once

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "hy2/quic.hpp"
#include "hy2/server_iface.hpp"
#include "hy2/protocol.hpp"

namespace hy2::h3sess {

// Congestion / bandwidth negotiation settings for one served session.
// Mirrors core::server::Config semantics:
//   - the client reports its download bandwidth (auth request "rx");
//     the server uses it to drive its OWN send congestion control
//     (Brutal when > 0, otherwise the configured CC),
//   - the server advertises its own receive limit back to the client
//     ("Hysteria-CC-RX") so the client can do the same for uploads.
struct HySessionConfig {
    bool udpEnabled = true;
    bool ignoreClientBandwidth = false;
    uint64_t bandwidthMaxTx = 0; // bytes/s cap for server -> client (0 = unlimited)
    uint64_t bandwidthMaxRx = 0; // bytes/s advertised to the client (0 = unlimited)
    std::string congestionType = "bbr";
    std::string bbrProfile;
    bool disableLossCompensation = false;
};

// One authenticated client connection served by HyServer.
class HySession : public std::enable_shared_from_this<HySession> {
public:
    HySession(std::shared_ptr<IQuicConnection> conn,
              server::Authenticator* auth,
              server::Outbound* outbound,
              const HySessionConfig& config);
    ~HySession();

    // Runs the auth handshake (blocking). Returns true on success.
    bool Auth();

    // Serves streams + datagrams until the connection dies.
    void Serve();

    void Stop();

private:
    void ServeStream(std::shared_ptr<IQuicStream> st);
    void RunUdpRelay();

    std::shared_ptr<IQuicConnection> conn_;
    server::Authenticator* auth_;
    server::Outbound* outbound_;
    HySessionConfig config_;
    bool udpEnabled_ = false;

    std::atomic<bool> stop_{false};
};

} // namespace hy2::h3sess
