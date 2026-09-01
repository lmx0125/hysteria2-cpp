// congestion.hpp - Congestion control interfaces mirroring quic-go's
// congestion package surface used by the original Go code (brutal/bbr/pacer).
#pragma once

#include <memory>
#include <vector>

#include "hy2/common.hpp"

namespace hy2::cc {

// AckedPacketInfo / LostPacketInfo mirror quic-go's congestion types.
struct AckedPacketInfo {
    PacketNumber packetNumber = 0;
    MonoTime TimeReceived{};
};

struct LostPacketInfo {
    PacketNumber packetNumber = 0;
    MonoTime TimeSent{};
};

// RTTStatsProvider mirrors quic-go congestion.RTTStatsProvider.
class RTTStatsProvider {
public:
    virtual ~RTTStatsProvider() = default;
    virtual Duration MinRTT() const = 0;
    virtual Duration LatestRTT() const = 0;
    virtual Duration SmoothedRTT() const = 0;
    virtual Duration MeanDeviation() const = 0;
};

// CongestionControl mirrors the interface set that brutal.BratalSender and
// bbr.BbrSender implement in the Go code.
class CongestionControl {
public:
    virtual ~CongestionControl() = default;

    virtual void SetRTTStatsProvider(RTTStatsProvider* rttStats) = 0;

    virtual MonoTime TimeUntilSend(ByteCount bytesInFlight) = 0;
    virtual bool HasPacingBudget(MonoTime now) = 0;
    virtual bool CanSend(ByteCount bytesInFlight) = 0;
    virtual ByteCount GetCongestionWindow() = 0;

    virtual void OnPacketSent(MonoTime sentTime, ByteCount bytesInFlight,
                              PacketNumber packetNumber, ByteCount bytes,
                              bool isRetransmittable) = 0;

    virtual void OnPacketAcked(PacketNumber number, ByteCount ackedBytes,
                               ByteCount priorInFlight, MonoTime eventTime) = 0;

    // Legacy single-packet loss notification (kept as a stub in both impls).
    virtual void OnCongestionEvent(PacketNumber number, ByteCount lostBytes,
                                   ByteCount priorInFlight) = 0;

    // Batched congestion event - where BrutalSender does its ack-rate sampling.
    virtual void OnCongestionEventEx(ByteCount priorInFlight, MonoTime eventTime,
                                     const std::vector<AckedPacketInfo>& ackedPackets,
                                     const std::vector<LostPacketInfo>& lostPackets) = 0;

    virtual void SetMaxDatagramSize(ByteCount size) = 0;

    virtual bool InSlowStart() = 0;
    virtual bool InRecovery() = 0;
    virtual void MaybeExitSlowStart() = 0;
    virtual void OnRetransmissionTimeout(bool packetsRetransmitted) = 0;
};

} // namespace hy2::cc
