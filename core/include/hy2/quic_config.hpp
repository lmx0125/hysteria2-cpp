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
    Duration KeepAlivePeriod{}; // client only
    bool DisablePathMTUDiscovery = false; // may be overridden on unsupported platforms
    bool DisableGSO = false;
    bool DisableChromeParrot = false; // client only; Chrome parroting on by default
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
