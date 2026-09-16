#if HY2_WITH_QUIC_BACKEND
// hy_server.hpp - Full Hysteria2 server facade over the real QUIC backend:
// Ngtcp2Listener + per-connection HySession (H3 auth + TCP/UDP proxying).
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "hy2/quic_backend/ngtcp2_listener.hpp"
#include "hy2/h3/hy_server_session.hpp"
#include "hy2/server_iface.hpp"

namespace hy2::h3sess {

struct HyServerParams {
    std::string bindAddr = "127.0.0.1";
    uint16_t port = 0;
    std::string certPem;
    std::string keyPem;
    bool udpEnabled = true;

    // Congestion / bandwidth negotiation (see HySessionConfig):
    //   bandwidthMaxTx: cap for server -> client (bytes/s, 0 = unlimited)
    //   bandwidthMaxRx: advertised client -> server cap (bytes/s, 0 = the
    //                   client uses its own configured upload bandwidth)
    //   ignoreClientBandwidth: always use the configured CC instead of
    //                   honoring the client's requested download rate.
    bool ignoreClientBandwidth = false;
    uint64_t bandwidthMaxTx = 0;
    uint64_t bandwidthMaxRx = 0;
    std::string congestionType = "bbr";
    std::string bbrProfile;
    bool disableLossCompensation = false;
};

// Session registry shared between HyServer and its detached per-connection
// worker threads. Owned via shared_ptr so a worker finishing after the
// HyServer was destroyed can still safely remove its (already gone) entry.
struct HySessionRegistry {
    std::mutex mu;
    std::vector<std::shared_ptr<HySession>> list;
};

class HyServer {
public:
    HyServer(const HyServerParams& params,
             server::Authenticator* auth,
             server::Outbound* outbound);
    ~HyServer();

    uint16_t Port() const { return port_; }
    // Stops accepting and closes everything.
    void Stop();

private:
    void AcceptLoop();

    HyServerParams params_;
    server::Authenticator* auth_ = nullptr;
    server::Outbound* outbound_ = nullptr;

    std::shared_ptr<quic_backend::Ngtcp2Listener> listener_;
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread acceptThread_;
    std::shared_ptr<HySessionRegistry> reg_ =
        std::make_shared<HySessionRegistry>();
};

} // namespace hy2::h3sess

#endif // HY2_WITH_QUIC_BACKEND
