// mimic_common.hpp - Shared mimic types and configuration.
// Mimic disguises UDP as TCP by rewriting packets in the kernel.
// On Linux, uses XDP/BPF; on Windows, user-mode fallback.
#pragma once

#include "hy2/platform/platform_common.hpp"

namespace hy2::platform {

// Filter generation helpers (shared between platforms)
std::vector<std::string> GenerateMimicFilters(MimicRole role,
                                               const std::vector<std::string>& addresses);

// Parse a filter string and extract the address part
std::string ParseFilterAddress(const std::string& filter);

} // namespace hy2::platform
