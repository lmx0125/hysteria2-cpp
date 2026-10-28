// brutal.hpp - BrutalSender. Rewrite of core/internal/congestion/brutal/brutal.go.
#pragma once

#include <array>

#include "hy2/common.hpp"
#include "hy2/congestion.hpp"
#include "hy2/pacer.hpp"

namespace hy2::cc {

constexpr int kPktInfoSlotCount = 5; // slot index is based on seconds, so this is basically how many seconds we sample
constexpr int kMinSampleCount = 50;
constexpr double kMinAckRate = 0.8;
constexpr int kCongestionWindowMultiplier = 2;

class BrutalSender : public CongestionControl {
public:
    explicit BrutalSender(uint64_t bps, bool disableLossCompensation);

    void SetRTTStatsProvider(RTTStatsProvider* rttStats) override { rttStats_ = rttStats; }

    MonoTime TimeUntilSend(ByteCount bytesInFlight) override;
    bool HasPacingBudget(MonoTime now) override;
    bool CanSend(ByteCount bytesInFlight) override;
    ByteCount GetCongestionWindow() override;

    void OnPacketSent(MonoTime sentTime, ByteCount bytesInFlight,
                      PacketNumber packetNumber, ByteCount bytes,
                      bool isRetransmittable) override;

    void OnPacketAcked(PacketNumber number, ByteCount ackedBytes,
                       ByteCount priorInFlight, MonoTime eventTime) override;

    void OnCongestionEvent(PacketNumber number, ByteCount lostBytes,
                           ByteCount priorInFlight) override;

    void OnCongestionEventEx(ByteCount priorInFlight, MonoTime eventTime,
                             const std::vector<AckedPacketInfo>& ackedPackets,
                             const std::vector<LostPacketInfo>& lostPackets) override;

    void SetMaxDatagramSize(ByteCount size) override;

    bool InSlowStart() override { return false; }
    bool InRecovery() override { return false; }
    void MaybeExitSlowStart() override {}
    void OnRetransmissionTimeout(bool) override {}

    // Exposed for testing / debugging.
    double AckRate() const { return ackRate_; }
    // Declared fixed send rate (bytes per second); the ngtcp2 backend arms its
    // in-stack Brutal controller with it.
    ByteCount BrutalRate() const override { return bps_; }

    bool BrutalDisableLossCompensation() const override {
        return disableLossCompensation_;
    }

private:
    struct PktInfo {
        int64_t Timestamp = 0;
        uint64_t AckCount = 0;
        uint64_t LossCount = 0;
    };

    void updateAckRate(int64_t currentTimestamp);
    bool canPrintAckRate(int64_t currentTimestamp) const;
    void debugPrint(const std::string& s) const;

    RTTStatsProvider* rttStats_ = nullptr;
    ByteCount bps_ = 0;
    ByteCount maxDatagramSize_ = kInitialPacketSize;
    // NOTE: declaration order matters - ackRate_ MUST be initialized before
    // pacer_, because pacer_'s constructor invokes getBandwidth_(), whose
    // lambda reads bps_ / ackRate_.
    double ackRate_ = 1.0;
    Pacer pacer_;

    std::array<PktInfo, kPktInfoSlotCount> pktInfoSlots_{};

    bool disableLossCompensation_ = false;

    bool debug_ = false;
    int64_t lastAckPrintTimestamp_ = 0;
};

} // namespace hy2::cc
