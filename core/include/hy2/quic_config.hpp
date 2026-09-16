// quic_config.hpp - QUIC/TLS configuration structs mirroring the subsets of
// quic-go's quic.Config / tls.Config exposed by hysteria configs.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "hy2/common.hpp"

namespace hy2 {

struct QuicConfig {
    uint64_t InitialStreamReceiveWindow = 0;
    uint64_t MaxStreamReceiveWindow = 0;
    uint64_t InitialConnectionReceiveWindow = 0;
    uint64_t MaxConnectionReceiveWindow = 0;
    int64_t MaxIncomingStreams = 0;
    Duration MaxIdleTimeout{};
    // HandshakeTimeout bounds the wait for the QUIC handshake to complete
    // (stream open blocks on it).  Zero = 10s default; node probing uses a
    // much shorter one.
    Duration HandshakeTimeout{};
    Duration KeepAlivePeriod{}; // client only
    // QUIC-level congestion control: "bbr" (default), "cubic" or "reno".
    // "brutal" maps to BBR because ngtcp2 only ships built-in controllers.
    std::string CongestionControl;
    // BrutalRate is this endpoint's declared send rate in bytes per second.
    // Non-zero selects the fixed-rate, loss-insensitive "Brutal" congestion
    // controller (Hysteria's sender) instead of a loss-responsive one.
    uint64_t BrutalRate = 0;
    bool DisablePathMTUDiscovery = false; // may be overridden on unsupported platforms
    bool DisableGSO = false;
    bool DisableChromeParrot = false; // client only; Chrome parroting on by default
    // Client only: bind the QUIC socket to this local IPv4/IPv6 address before
    // connecting. Used by the TUN proxy to pin the tunnel's own transport to
    // the physical interface: without it, a route-table change (the TUN's
    // default route) can capture the client's packets into the TUN and the
    // handshake can never complete.
    std::string LocalBindAddr;
};

// Simplified server-side TLS configuration. Real certificate handling is a
// transport-backend concern; these fields carry what protocol code needs.
struct TlsServerConfig {
    std::vector<std::string> CertificatesPEM; // cert chains (PEM)
    std::vector<std::string> PrivateKeysPEM;  // matching keys (PEM)
    std::vector<std::string> ClientCAPEM;     // when non-empty => RequireAndVerifyClientCert
};

// Simplified client-side TLS configuration.
struct TlsClientConfig {
    std::string ServerName;
    bool InsecureSkipVerify = false;
    std::vector<std::string> RootCAsPEM;
    std::vector<uint8_t> ECHConfigList;
};

} // namespace hy2
