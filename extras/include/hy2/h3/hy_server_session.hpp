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

// One authenticated client connection served by HyServer.
class HySession : public std::enable_shared_from_this<HySession> {
public:
    HySession(std::shared_ptr<IQuicConnection> conn,
              server::Authenticator* auth,
              server::Outbound* outbound,
              bool udpEnabled);
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
    bool udpEnabled_ = false;

    std::atomic<bool> stop_{false};
};

} // namespace hy2::h3sess
