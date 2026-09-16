#include "hy2/quic_backend/quic_backend_factory.hpp"

#include <iostream>

#include "hy2/quic_backend/ngtcp2_connection.hpp"
#include "hy2/quic_backend/ngtcp2_listener.hpp"
#include "hy2/quic_backend/h3_auth.hpp"
#include "hy2/client.hpp"

namespace hy2::quic_backend {

std::shared_ptr<IQuicConnection> CreateQuicConnection(
    const std::string& remoteAddr,
    const std::string& serverName,
    const QuicConfig& quicCfg,
    bool insecureSkipVerify) {

    Ngtcp2Connection::ClientParams params;
    params.remoteAddr = remoteAddr;
    params.serverName = serverName;
    params.insecureSkipVerify = insecureSkipVerify;
    params.quicCfg = quicCfg;
    params.localBindAddr = quicCfg.LocalBindAddr;

    auto conn = Ngtcp2Connection::Connect(params);
    if (!conn) {
        throw ConnectError("failed to create ngtcp2 connection to " + remoteAddr);
    }
    return conn;
}

std::unique_ptr<client::ClientTransport> CreateH3AuthTransport(
    const std::string& serverAddr,
    const std::string& serverName,
    bool insecureSkipVerify) {

    H3AuthRoundTripper::Params params;
    params.serverAddr = serverAddr;
    params.serverName = serverName;
    params.insecureSkipVerify = insecureSkipVerify;

    return std::make_unique<H3AuthRoundTripper>(std::move(params));
}

static H3AuthRoundTripper* g_transport = nullptr;

void RegisterBackend(const std::string& serverAddr,
                     const std::string& serverName,
                     bool insecureSkipVerify) {
    static H3AuthRoundTripper transport({
        serverAddr,
        serverName,
        insecureSkipVerify
    });
    g_transport = &transport;
    client::SetGlobalClientTransport(g_transport);
}

} // namespace hy2::quic_backend
