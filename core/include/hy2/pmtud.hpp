// pmtud.hpp - Path MTU discovery availability. Rewrite of
// core/internal/pmtud/{avail,unavail}.go: on platforms where QUIC PMTUD is
// supported this stays false; platform backends may override.
#pragma once

namespace hy2 {

// When true, QUIC path MTU discovery is disabled regardless of config
// (mirrors pmtud.DisablePathMTUDiscovery).
constexpr bool DisablePathMTUDiscovery = false;

} // namespace hy2
