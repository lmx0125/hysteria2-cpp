// bbr_sender.hpp - rewrite of core/internal/congestion/bbr/bbr_sender.go.
//
// BbrSender implements BBR congestion control algorithm. BBR aims to estimate
// the current available Bottleneck Bandwidth and RTT (hence the name), and
// regulates the pacing rate and the size of the congestion window based on
// those signals.
//
// BBR relies on pacing in order to function properly. Do not use BBR when
// pacing is disabled.
#pragma once

#include <cstdint>
#include <string>

#include "hy2/common.hpp"
#include "hy2/congestion.hpp"
#include "hy2/error.hpp"
#include "hy2/pacer.hpp"
#include "hy2/bbr.hpp"
#include "hy2/bbr/bandwidth.hpp"
#include "hy2/bbr/bandwidth_sampler.hpp"
#include "hy2/bbr/windowed_filter.hpp"

namespace hy2::bbr {

constexpr ByteCount kMinBps = 65536; // 64 KB/s

constexpr int kInitialCongestionWindowPackets = 32;
constexpr int kMinCongestionWindowPackets = 4;

// Constants based on TCP defaults.
// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
// Does not inflate the pacing rate.
// The gain used for the STARTUP, equal to 2/ln(2).
constexpr double kDefaultHighGain = 2.885;
// The newly derived CWND gain for STARTUP, 2.
constexpr double kDerivedHighCwndGain = 2.0;

// The cycle of gains used during the PROBE_BW stage.
extern const double kPacingGain[8];

// The length of the gain cycle.
constexpr int kGainCycleLength = 8; // len(kPacingGain)
// The size of the bandwidth filter window, in round-trips.
constexpr RoundTripCount kBandwidthWindowSize = kGainCycleLength + 2;

// The time after which the current min_rtt value expires.
constexpr Duration kMinRttExpiry = Duration::FromSeconds(10);
// The minimum time the connection can spend in PROBE_RTT mode.
constexpr Duration kProbeRttTime = Duration::FromMillis(200);
// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
// will exit the STARTUP mode.
constexpr double kStartupGrowthTarget = 1.25;
constexpr std::int64_t kRoundTripsWithoutGrowthBeforeExitingStartup = 3;

// Flag.
constexpr int kDefaultStartupFullLossCount = 8;
constexpr double kQuicBbr2DefaultLossThreshold = 0.02;

// Constants exposed from quic-go's congestion/protocol packages that the Go
// implementation relies on (apernet/quic-go @ 184d081eef3e).
constexpr ByteCount kMaxCongestionWindowPackets = 20000; // protocol.MaxCongestionWindowPackets
constexpr std::int32_t kPacketsPerConnectionID = 10000;  // protocol.PacketsPerConnectionID
constexpr ByteCount kMaxPacketBufferSize = 1452;         // protocol.MaxPacketBufferSize
constexpr ByteCount kMinInitialPacketSize = 1200;        // congestion.MinInitialPacketSize

enum class BbrMode {
    // Startup phase of the connection.
    kStartup,
    // After achieving the highest possible bandwidth during the startup, lower
    // the pacing rate in order to drain the queue.
    kDrain,
    // Cruising mode.
    kProbeBw,
    // Temporarily slow down sending in order to empty the buffer and measure
    // the real minimum RTT.
    kProbeRtt,
};

// Indicates how the congestion control limits the amount of bytes in flight.
enum class BbrRecoveryState {
    // Do not limit.
    kNotInRecovery,
    // Allow an extra outstanding byte for each byte acknowledged.
    kConservation,
    // Allow two extra outstanding bytes for each byte acknowledged (slow
    // start).
    kGrowth,
};

struct ProfileConfig {
    double HighGain = 0.0;
    double HighCwndGain = 0.0;
    double CongestionWindowGainConstant = 0.0;
    std::int64_t NumStartupRtts = 0;
    bool DrainToTarget = false;
    bool DetectOvershooting = false;
    std::uint8_t BytesLostMultiplier = 0;
    bool EnableAckAggregationStartup = false;
    bool ExpireAckAggregationStartup = false;
    bool EnableOverestimateAvoidance = false;
    bool ReduceExtraAckedOnBandwidthIncrease = false;
};

ProfileConfig ConfigForProfile(const Profile& profile);

ByteCount MinCongestionWindowForMaxDatagramSize(ByteCount maxDatagramSize);

ByteCount ScaleByteWindowForDatagramSize(ByteCount window, ByteCount oldMaxDatagramSize,
                                         ByteCount newMaxDatagramSize);

ByteCount BdpFromRttAndBandwidth(Duration rtt, Bandwidth bandwidth);

class BbrSender final : public cc::CongestionControl {
public:
    BbrSender(Clock& clock, ByteCount initialMaxDatagramSize,
              ByteCount initialCongestionWindow, ByteCount initialMaxCongestionWindow,
              const Profile& profile);
    ~BbrSender() override = default;

    void SetRTTStatsProvider(cc::RTTStatsProvider* rttStats) override { rttStats_ = rttStats; }

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
                             const std::vector<cc::AckedPacketInfo>& ackedPackets,
                             const std::vector<cc::LostPacketInfo>& lostPackets) override;

    void SetMaxDatagramSize(ByteCount size) override;

    bool InSlowStart() override { return mode_ == BbrMode::kStartup; }
    bool InRecovery() override { return recoveryState_ != BbrRecoveryState::kNotInRecovery; }
    void MaybeExitSlowStart() override {}
    void OnRetransmissionTimeout(bool /*packetsRetransmitted*/) override {}

    Bandwidth PacingRate();

    // --- Accessors mirroring package-private fields of the Go type; the
    // original tests live in the same package and inspect these directly. ---
    const Profile& ProfileName() const { return profile_; }
    double HighGainValue() const { return highGain_; }
    double HighCwndGainValue() const { return highCwndGain_; }
    double DrainGainValue() const { return drainGain_; }
    double PacingGainValue() const { return pacingGain_; }
    double CongestionWindowGainValue() const { return congestionWindowGain_; }
    double CongestionWindowGainConstantValue() const { return congestionWindowGainConstant_; }
    std::int64_t NumStartupRttsValue() const { return numStartupRtts_; }
    bool DrainToTargetEnabled() const { return drainToTarget_; }
    bool DetectOvershootingEnabled() const { return detectOvershooting_; }
    std::uint8_t BytesLostMultiplierValue() const { return bytesLostMultiplierWhileDetectingOvershooting_; }
    bool AckAggregationDuringStartupEnabled() const { return enableAckAggregationDuringStartup_; }
    bool ExpireAckAggregationInStartupEnabled() const { return expireAckAggregationInStartup_; }
    bool OverestimateAvoidanceEnabled() const { return sampler_.IsOverestimateAvoidanceEnabled(); }
    bool ReduceExtraAckedOnBandwidthIncreaseEnabled() const {
        return sampler_.maxAckHeightTracker().ReduceExtraAckedOnBandwidthIncrease();
    }
    bool IsAtFullBandwidth() const { return isAtFullBandwidth_; }
    BbrMode Mode() const { return mode_; }
    ByteCount InitialCongestionWindowBytes() const { return initialCongestionWindow_; }
    ByteCount MaxCongestionWindowBytes() const { return maxCongestionWindow_; }
    ByteCount MinCongestionWindowBytes() const { return minCongestionWindow_; }
    ByteCount RecoveryWindowBytes() const { return recoveryWindow_; }
    BandwidthSampler& Sampler() { return sampler_; }

    void SetCongestionWindowForTest(ByteCount v) { congestionWindow_ = v; }
    void SetRecoveryWindowForTest(ByteCount v) { recoveryWindow_ = v; }

private:
    void ApplyProfile(const Profile& profile);

    Duration RttStatsMinRTT() const;

    Duration GetMinRtt();
    ByteCount GetTargetCongestionWindow(double gain);
    ByteCount ProbeRttCongestionWindow();
    bool MaybeUpdateMinRtt(MonoTime now, Duration sampleMinRtt);

    void EnterStartupMode(MonoTime now);
    void EnterProbeBandwidthMode(MonoTime now);

    bool UpdateRoundTripCounter(PacketNumber lastAckedPacket);
    void UpdateGainCyclePhase(MonoTime now, ByteCount priorInFlight, bool hasLosses);

    void CheckIfFullBandwidthReached(const SendTimeState& lastPacketSendState);
    void MaybeAppLimited(ByteCount bytesInFlight);
    void MaybeExitStartupOrDrain(MonoTime now);
    void MaybeEnterOrExitProbeRtt(MonoTime now, bool isRoundStart, bool minRttExpired);
    void UpdateRecoveryState(PacketNumber lastAckedPacket, bool hasLosses, bool isRoundStart);
    void CalculatePacingRate(ByteCount bytesLost);
    void CalculateCongestionWindow(ByteCount bytesAcked, ByteCount excessAcked);
    void CalculateRecoveryWindow(ByteCount bytesAcked, ByteCount bytesLost);
    bool ShouldExitStartupDueToLoss(const SendTimeState& lastPacketSendState);

    ByteCount BandwidthForPacer();
    Bandwidth BandwidthEstimate();
    void RescalePacketSizedWindows(ByteCount maxDatagramSize);
    void DebugPrint(const std::string& message);

    Clock& clock_;
    cc::RTTStatsProvider* rttStats_ = nullptr;

    BbrMode mode_;

    // Bandwidth sampler provides BBR with the bandwidth measurements at
    // individual points.
    BandwidthSampler sampler_;

    // The number of the round trips that have occurred during the connection.
    RoundTripCount roundTripCount_ = 0;

    // The packet number of the most recently sent packet.
    PacketNumber lastSentPacket_;
    // Acknowledgement of any packet after |currentRoundTripEnd_| will cause the
    // round trip counter to advance.
    PacketNumber currentRoundTripEnd_;

    // Number of congestion events with some losses, in the current round.
    std::uint64_t numLossEventsInRound_ = 0;
    // Number of total bytes lost in the current round.
    ByteCount bytesLostInRound_ = 0;

    // The filter that tracks the maximum bandwidth over the multiple recent
    // round-trips.
    WindowedFilter<Bandwidth, RoundTripCount> maxBandwidth_;

    // Minimum RTT estimate. Automatically expires within 10 seconds (and
    // triggers PROBE_RTT mode) if no new value is sampled during that period.
    Duration minRtt_{};
    // The time at which the current value of |minRtt_| was assigned.
    MonoTime minRttTimestamp_{};

    // The maximum allowed number of bytes in flight.
    ByteCount congestionWindow_;
    // The initial value of the |congestionWindow_|.
    ByteCount initialCongestionWindow_;
    // The largest value the |congestionWindow_| can achieve.
    ByteCount maxCongestionWindow_;
    // The smallest value the |congestionWindow_| can achieve.
    ByteCount minCongestionWindow_;

    // The BBR profile used by the sender.
    Profile profile_;
    // The pacing gain applied during the STARTUP phase.
    double highGain_;
    // The CWND gain applied during the STARTUP phase.
    double highCwndGain_;
    // The pacing gain applied during the DRAIN phase.
    double drainGain_;
    // The current pacing rate of the connection.
    Bandwidth pacingRate_ = 0;
    // The gain currently applied to the pacing rate.
    double pacingGain_;
    // The gain currently applied to the congestion window.
    double congestionWindowGain_;
    // The gain used for the congestion window during PROBE_BW. Latched from
    // quic_bbr_cwnd_gain flag.
    double congestionWindowGainConstant_;
    // The number of RTTs to stay in STARTUP mode. Defaults to 3.
    std::int64_t numStartupRtts_;

    // Number of round-trips in PROBE_BW mode, used for determining the current
    // pacing gain cycle.
    int cycleCurrentOffset_ = 0;
    // The time at which the last pacing gain cycle was started.
    MonoTime lastCycleStart_{};

    // Indicates whether the connection has reached the full bandwidth mode.
    bool isAtFullBandwidth_ = false;
    // Number of rounds during which there was no significant bandwidth
    // increase.
    std::int64_t roundsWithoutBandwidthGain_ = 0;
    // The bandwidth compared to which the increase is measured.
    Bandwidth bandwidthAtLastRound_ = 0;

    // Set to true upon exiting quiescence.
    bool exitingQuiescence_ = false;

    // Time at which PROBE_RTT has to be exited. Zero indicates that the time is
    // yet unknown as the number of packets in flight has not reached the
    // required value.
    MonoTime exitProbeRttAt_{};
    // Indicates whether a round-trip has passed since PROBE_RTT became active.
    bool probeRttRoundPassed_ = false;

    // Indicates whether the most recent bandwidth sample was marked as
    // app-limited.
    bool lastSampleIsAppLimited_ = false;
    // Indicates whether any non app-limited samples have been recorded.
    bool hasNoAppLimitedSample_ = false;

    // Current state of recovery.
    BbrRecoveryState recoveryState_;
    // Receiving acknowledgement of a packet after |endRecoveryAt_| will cause
    // BBR to exit the recovery mode. A value above zero indicates at least one
    // loss has been detected, so it must not be set back to zero.
    PacketNumber endRecoveryAt_;
    // A window used to limit the number of bytes in flight during loss
    // recovery.
    ByteCount recoveryWindow_;

    // When true, add the most recent ack aggregation measurement during
    // STARTUP.
    bool enableAckAggregationDuringStartup_ = false;
    // When true, expire the windowed ack aggregation values in STARTUP when
    // bandwidth increases more than 25%.
    bool expireAckAggregationInStartup_ = false;

    // If true, will not exit low gain mode until bytes_in_flight drops below
    // BDP or it's time for high gain mode.
    bool drainToTarget_ = false;

    // If true, slow down pacing rate in STARTUP when overshooting is detected.
    bool detectOvershooting_ = false;
    // Bytes lost while detectOvershooting_ is true.
    ByteCount bytesLostWhileDetectingOvershooting_ = 0;
    // Slow down pacing rate if bytesLostWhileDetectingOvershooting_ *
    // bytesLostMultiplierWhileDetectingOvershooting_ > IW.
    std::uint8_t bytesLostMultiplierWhileDetectingOvershooting_ = 2;
    // When overshooting is detected, do not drop pacing_rate_ below this value
    // / min_rtt.
    ByteCount cwndToCalculateMinPacingRate_;

    // Max congestion window when adjusting network parameters.
    ByteCount maxCongestionWindowWithNetworkParametersAdjusted_;

    // Params.
    ByteCount maxDatagramSize_;
    // Recorded on packet sent; equivalent to unacked_packets bytes in flight.
    ByteCount bytesInFlight_ = 0;

    bool debug_ = false;

    // DECLARATION ORDER MATTERS: Pacer's constructor immediately queries the
    // bandwidth callback (BandwidthForPacer -> PacingRate -> pacingRate_ /
    // highGain_ / initialCongestionWindow_ / minRtt_ / maxDatagramSize_), so
    // pacer_ must be constructed LAST, after every member it reads. Keep it at
    // the end of this list (and last in the constructor's init list) - see the
    // same note in brutal.hpp, which hit this first.
    cc::Pacer pacer_;
};

} // namespace hy2::bbr
