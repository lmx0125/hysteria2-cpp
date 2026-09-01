// bandwidth.hpp - rewrite of core/internal/congestion/bbr/bandwidth.go.
#pragma once

#include <cstdint>

#include "hy2/common.hpp"

namespace hy2::bbr {

// Bandwidth of a connection, in bits per second (Go: type Bandwidth uint64).
using Bandwidth = std::uint64_t;

constexpr Bandwidth kBitsPerSecond = 1;
constexpr Bandwidth kBytesPerSecond = 8 * kBitsPerSecond;

constexpr Bandwidth kInfBandwidth = UINT64_MAX; // math.MaxUint64

constexpr std::int64_t kSecondNanos = 1000000000LL; // time.Second in ns

// BandwidthFromDelta calculates the bandwidth from a number of bytes and a
// time delta. Mirrors Go's unsigned wrap-around arithmetic exactly:
// Bandwidth(bytes) * Bandwidth(time.Second) / Bandwidth(delta) * BytesPerSecond.
inline Bandwidth BandwidthFromDelta(ByteCount bytes, Duration delta) {
    return static_cast<Bandwidth>(static_cast<std::uint64_t>(bytes) *
                                      static_cast<std::uint64_t>(kSecondNanos) /
                                      static_cast<std::uint64_t>(delta.ns)) *
           kBytesPerSecond;
}

} // namespace hy2::bbr
