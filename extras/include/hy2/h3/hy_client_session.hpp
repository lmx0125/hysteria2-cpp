// hy_client_session.hpp - Real-QUIC client implementing the Hysteria2
// application protocol against an OFFICIAL server:
//
//   hy2-cpp Client ──HTTP/3 POST /auth──▶ Official Server (quic-go)
//        ◀──────────── 233 + headers ──────┘
//   TCP(addr): new stream + TCPRequest, wait TCPResponse, relay
//   UDP():     datagrams with UDPMessage
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "hy2/quic.hpp"
#include "hy2/protocol.hpp"
#include "hy2/frag.hpp"

namespace hy2::h3sess {

class HyClient {
public:
    HyClient(std::shared_ptr<IQuicConnection> conn, std::string auth);
    ~HyClient();

    // Blocking auth. Throws std::runtime_error on failure (mirrors
    // coreErrs.AuthError / ConnectError semantics loosely).
    void Auth();

    // Opens a proxied TCP stream. Returns nullptr + msg on dial error.
    std::shared_ptr<IQuicStream> TCP(const std::string& addr,
                                     std::string* errMsg = nullptr);

    // Sends a datagram to addr.
    void UDPSend(uint32_t sessionID, const std::string& addr,
                 const uint8_t* data, size_t n);

    // Blocks for the next inbound datagram; returns parsed message.
    proto::UDPMessage UDPReceive();

    void Close();

private:
    std::shared_ptr<IQuicConnection> conn_;
    std::string auth_;
    bool udpEnabled_ = false;
    frag::Defragger udpDefrag_;
    std::thread drainThread_;
    std::atomic<bool> closed_{false};
};

} // namespace hy2::h3sess
