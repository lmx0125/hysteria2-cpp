// bbr.hpp - BBR congestion control contract.
// Implementation mirrors core/internal/congestion/bbr/*.go (bbr_sender.go,
// bandwidth_sampler.go, windowed_filter.go, packet_number_indexed_queue.go,
// ringbuffer.go, clock.go).
#pragma once

#include <memory>
#include <string>

#include "hy2/common.hpp"
#include "hy2/congestion.hpp"

namespace hy2::bbr {

using Profile = std::string;

constexpr const char* ProfileConservative = "conservative";
constexpr const char* ProfileStandard = "standard";
constexpr const char* ProfileAggressive = "aggressive";

// Clock abstracts time for the sender (mirrors bbr.Clock / DefaultClock).
class Clock {
public:
    virtual ~Clock() = default;
    virtual MonoTime Now() = 0;
};

class DefaultClock : public Clock {
public:
    MonoTime Now() override { return MonoTime::Now(); }
};

// ParseProfile normalizes a profile string ("", standard, conservative,
// aggressive, case-insensitive). Throws Error("unsupported BBR profile %q")
// on unknown values - message matches the Go implementation.
Profile ParseProfile(const std::string& profile);

// GetInitialPacketSize guesses the datagram size from the remote address
// (IPv6 => 1232 bytes payload guess, IPv4 => 1252, unknown => 1352).
ByteCount GetInitialPacketSize(const std::string& remoteAddr);

// NewBbrSender creates a BBR sender (mirrors bbr.NewBbrSender).
std::shared_ptr<cc::CongestionControl> NewBbrSender(Clock& clock,
                                                    ByteCount initialCongestionWindow,
                                                    const Profile& profile);

} // namespace hy2::bbr
