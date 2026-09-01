#pragma once

#include <memory>

#include "hy2/quic.hpp"
#include "hy2/quic_config.hpp"
#include "hy2/client.hpp"

namespace hy2::quic_backend {

// ---------------------------------------------------------------------------
// CreateQuicConnection: creates a real ngtcp2-backed QUIC connection.
// This is the "pluggable backend" entry point that SetGlobalQuicBackend
// expects. Client/server session code calls this instead of mocking.
// ---------------------------------------------------------------------------
std::shared_ptr<IQuicConnection> CreateQuicConnection(
    const std::string& remoteAddr,
    const std::string& serverName,
    const QuicConfig& quicCfg,
    bool insecureSkipVerify = false);

// ---------------------------------------------------------------------------
// CreateH3AuthTransport: creates the HTTP/3 auth round tripper.
// ---------------------------------------------------------------------------
std::unique_ptr<client::ClientTransport> CreateH3AuthTransport(
    const std::string& serverAddr,
    const std::string& serverName,
    bool insecureSkipVerify = false);

// ---------------------------------------------------------------------------
// RegisterBackend: sets the global client transport + quic connection factory.
// After calling this, NewClient() will use the real ngtcp2 backend.
// ---------------------------------------------------------------------------
void RegisterBackend(const std::string& serverAddr,
                     const std::string& serverName,
                     bool insecureSkipVerify = false);

} // namespace hy2::quic_backend
