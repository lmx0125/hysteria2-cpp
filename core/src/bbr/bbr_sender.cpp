// bbr_sender.cpp - rewrite of core/internal/congestion/bbr/bbr_sender.go.
#include "hy2/bbr/bbr_sender.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>

namespace hy2::bbr {

namespace {

bool envDebugEnabled() {
    const char* v = std::getenv("HYSTERIA_BBR_DEBUG");
    if (v == nullptr) return false;
    std::string s(v);
    // Go strconv.ParseBool semantics: only these spell out true, everything
    // else (including "") parses as an error and is treated as false.
    return s == "1" || s == "t" || s == "T" || s == "true" || s == "TRUE" ||
           s == "True";
}

std::string hhmmssNow() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

std::string formatSpeed(Bandwidth bw) {
    double bwf = static_cast<double>(bw);
    const char* units[] = {"bps", "Kbps", "Mbps", "Gbps"};
    int unitIndex = 0;
    while (bwf > 1000 && unitIndex < 3) {
        bwf /= 1000;
        unitIndex++;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2f %s", bwf, units[unitIndex]);
    return buf;
}

// Decides whether the address string looks like a UDP address ("host:port"),
// which mirrors Go's addr.(*net.UDPAddr) type check for string addresses.
bool looksLikeUdpAddress(const std::string& addr) {
    if (addr.empty()) return false;
    std::size_t colon = addr.rfind(':');
    if (colon == std::string::npos) return false;
    std::string host = addr.substr(0, colon);
    std::string port = addr.substr(colon + 1);
    bool bracketed = false;
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
        bracketed = true;
    }
    if (!bracketed && host.find(':') != std::string::npos) return false; // bare IPv6, no port
    if (port.empty()) return false;
    int p = 0;
    for (char c : port) {
        if (c < '0' || c > '9') return false;
        p = p * 10 + (c - '0');
        if (p > 65535) return false;
    }
    return !host.empty();
}

} // namespace

const double kPacingGain[8] = {1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0};

Profile ParseProfile(const std::string& profile) {
    std::string normalized;
    normalized.reserve(profile.size());
    for (char c : profile) {
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (normalized.empty() || normalized == ProfileStandard) return ProfileStandard;
    if (normalized == ProfileConservative) return ProfileConservative;
    if (normalized == ProfileAggressive) return ProfileAggressive;
    throw Error("unsupported BBR profile \"" + profile + "\"");
}

ProfileConfig ConfigForProfile(const Profile& profile) {
    if (profile == ProfileConservative) {
        ProfileConfig cfg;
        cfg.HighGain = 2.25;
        cfg.HighCwndGain = 1.75;
        cfg.CongestionWindowGainConstant = 1.75;
        cfg.NumStartupRtts = 2;
        cfg.DrainToTarget = true;
        cfg.DetectOvershooting = true;
        cfg.BytesLostMultiplier = 1;
        cfg.EnableOverestimateAvoidance = true;
        cfg.ReduceExtraAckedOnBandwidthIncrease = true;
        return cfg;
    }
    if (profile == ProfileAggressive) {
        ProfileConfig cfg;
        cfg.HighGain = 3.0;
        cfg.HighCwndGain = 2.25;
        cfg.CongestionWindowGainConstant = 2.5;
        cfg.NumStartupRtts = 4;
        cfg.BytesLostMultiplier = 2;
        cfg.EnableAckAggregationStartup = true;
        cfg.ExpireAckAggregationStartup = true;
        return cfg;
    }
    ProfileConfig cfg;
    cfg.HighGain = kDefaultHighGain;
    cfg.HighCwndGain = kDerivedHighCwndGain;
    cfg.CongestionWindowGainConstant = 2.0;
    cfg.NumStartupRtts = kRoundTripsWithoutGrowthBeforeExitingStartup;
    cfg.BytesLostMultiplier = 2;
    return cfg;
}

ByteCount MinCongestionWindowForMaxDatagramSize(ByteCount maxDatagramSize) {
    return kMinCongestionWindowPackets * maxDatagramSize;
}

ByteCount ScaleByteWindowForDatagramSize(ByteCount window, ByteCount oldMaxDatagramSize,
                                         ByteCount newMaxDatagramSize) {
    if (oldMaxDatagramSize == newMaxDatagramSize) {
        return window;
    }
    return static_cast<ByteCount>(static_cast<std::uint64_t>(window) *
                                  static_cast<std::uint64_t>(newMaxDatagramSize) /
                                  static_cast<std::uint64_t>(oldMaxDatagramSize));
}

ByteCount BdpFromRttAndBandwidth(Duration rtt, Bandwidth bandwidth) {
    // Multiplication wraps modulo 2^64 exactly like in Go.
    std::int64_t product = static_cast<std::int64_t>(
        static_cast<std::uint64_t>(rtt.ns) * bandwidth);
    // congestion.ByteCount(rtt) * congestion.ByteCount(bandwidth) / BytesPerSecond / time.Second
    return product / static_cast<std::int64_t>(kBytesPerSecond) / kSecondNanos;
}

BbrSender::BbrSender(Clock& clock, ByteCount initialMaxDatagramSize,
                     ByteCount initialCongestionWindow, ByteCount initialMaxCongestionWindow,
                     const Profile& profile)
    : clock_(clock),
      mode_(BbrMode::kStartup),
      sampler_(kBandwidthWindowSize),
      lastSentPacket_(kInvalidPacketNumber),
      currentRoundTripEnd_(kInvalidPacketNumber),
      maxBandwidth_(kBandwidthWindowSize, MaxFilter{}),
      congestionWindow_(initialCongestionWindow),
      initialCongestionWindow_(initialCongestionWindow),
      maxCongestionWindow_(initialMaxCongestionWindow),
      minCongestionWindow_(MinCongestionWindowForMaxDatagramSize(initialMaxDatagramSize)),
      profile_(ProfileStandard),
      highGain_(kDefaultHighGain),
      highCwndGain_(kDerivedHighCwndGain),
      drainGain_(1.0 / kDefaultHighGain),
      pacingRate_(0),
      pacingGain_(1.0),
      congestionWindowGain_(1.0),
      congestionWindowGainConstant_(2.0),
      numStartupRtts_(kRoundTripsWithoutGrowthBeforeExitingStartup),
      recoveryState_(BbrRecoveryState::kNotInRecovery),
      endRecoveryAt_(kInvalidPacketNumber),
      recoveryWindow_(initialMaxCongestionWindow),
      bytesLostMultiplierWhileDetectingOvershooting_(2),
      cwndToCalculateMinPacingRate_(initialCongestionWindow),
      maxCongestionWindowWithNetworkParametersAdjusted_(initialMaxCongestionWindow),
      maxDatagramSize_(initialMaxDatagramSize),
      debug_(envDebugEnabled()),
      // Last: Pacer's constructor reads the members above (see bbr_sender.hpp).
      pacer_([this]() -> ByteCount { return BandwidthForPacer(); }) {
    ApplyProfile(profile);
    if (debug_) {
        DebugPrint("Profile: " + profile_);
    }

    EnterStartupMode(clock_.Now());
}

void BbrSender::ApplyProfile(const Profile& profile) {
    Profile p = profile.empty() ? Profile(ProfileStandard) : profile;
    ProfileConfig cfg = ConfigForProfile(p);
    profile_ = p;
    highGain_ = cfg.HighGain;
    highCwndGain_ = cfg.HighCwndGain;
    drainGain_ = 1.0 / cfg.HighGain;
    congestionWindowGainConstant_ = cfg.CongestionWindowGainConstant;
    numStartupRtts_ = cfg.NumStartupRtts;
    drainToTarget_ = cfg.DrainToTarget;
    detectOvershooting_ = cfg.DetectOvershooting;
    bytesLostMultiplierWhileDetectingOvershooting_ = cfg.BytesLostMultiplier;
    enableAckAggregationDuringStartup_ = cfg.EnableAckAggregationStartup;
    expireAckAggregationInStartup_ = cfg.ExpireAckAggregationStartup;
    if (cfg.EnableOverestimateAvoidance) {
        sampler_.EnableOverestimateAvoidance();
    }
    sampler_.SetReduceExtraAckedOnBandwidthIncrease(cfg.ReduceExtraAckedOnBandwidthIncrease);
}

MonoTime BbrSender::TimeUntilSend(ByteCount bytesInFlight) {
    (void)bytesInFlight;
    return pacer_.TimeUntilSend();
}

bool BbrSender::HasPacingBudget(MonoTime now) {
    return pacer_.Budget(now) >= maxDatagramSize_;
}

void BbrSender::OnPacketSent(MonoTime sentTime, ByteCount bytesInFlight,
                             PacketNumber packetNumber, ByteCount bytes,
                             bool isRetransmittable) {
    pacer_.SentPacket(sentTime, bytes);

    lastSentPacket_ = packetNumber;
    bytesInFlight_ = bytesInFlight;

    if (bytesInFlight == 0) {
        exitingQuiescence_ = true;
    }

    sampler_.OnPacketSent(sentTime, packetNumber, bytes, bytesInFlight, isRetransmittable);
}

bool BbrSender::CanSend(ByteCount bytesInFlight) {
    return bytesInFlight < GetCongestionWindow();
}

void BbrSender::OnPacketAcked(PacketNumber /*number*/, ByteCount /*ackedBytes*/,
                              ByteCount /*priorInFlight*/, MonoTime /*eventTime*/) {}

void BbrSender::OnCongestionEvent(PacketNumber /*number*/, ByteCount /*lostBytes*/,
                                  ByteCount /*priorInFlight*/) {}

void BbrSender::SetMaxDatagramSize(ByteCount s) {
    if (debug_) {
        DebugPrint("Max Datagram Size: " + std::to_string(s));
    }
    if (s < maxDatagramSize_) {
        throw Error("congestion BUG: decreased max datagram size from " +
                    std::to_string(maxDatagramSize_) + " to " + std::to_string(s));
    }
    ByteCount oldMinCongestionWindow = minCongestionWindow_;
    ByteCount oldInitialCongestionWindow = initialCongestionWindow_;
    RescalePacketSizedWindows(s);
    if (congestionWindow_ == oldMinCongestionWindow) {
        congestionWindow_ = minCongestionWindow_;
    } else if (congestionWindow_ == oldInitialCongestionWindow) {
        congestionWindow_ = initialCongestionWindow_;
    } else {
        congestionWindow_ =
            std::min(maxCongestionWindow_, std::max(congestionWindow_, minCongestionWindow_));
    }
    recoveryWindow_ = std::min(maxCongestionWindow_, std::max(recoveryWindow_, minCongestionWindow_));
    pacer_.SetMaxDatagramSize(s);
}

ByteCount BbrSender::GetCongestionWindow() {
    if (mode_ == BbrMode::kProbeRtt) {
        return ProbeRttCongestionWindow();
    }

    if (InRecovery()) {
        return std::min(congestionWindow_, recoveryWindow_);
    }

    return congestionWindow_;
}

void BbrSender::RescalePacketSizedWindows(ByteCount maxDatagramSize) {
    ByteCount oldMaxDatagramSize = maxDatagramSize_;
    maxDatagramSize_ = maxDatagramSize;
    initialCongestionWindow_ = ScaleByteWindowForDatagramSize(
        initialCongestionWindow_, oldMaxDatagramSize, maxDatagramSize);
    maxCongestionWindow_ = ScaleByteWindowForDatagramSize(maxCongestionWindow_,
                                                          oldMaxDatagramSize, maxDatagramSize);
    minCongestionWindow_ = MinCongestionWindowForMaxDatagramSize(maxDatagramSize);
    cwndToCalculateMinPacingRate_ = ScaleByteWindowForDatagramSize(
        cwndToCalculateMinPacingRate_, oldMaxDatagramSize, maxDatagramSize);
    maxCongestionWindowWithNetworkParametersAdjusted_ = ScaleByteWindowForDatagramSize(
        maxCongestionWindowWithNetworkParametersAdjusted_, oldMaxDatagramSize, maxDatagramSize);
}

void BbrSender::OnCongestionEventEx(ByteCount priorInFlight, MonoTime eventTime,
                                    const std::vector<cc::AckedPacketInfo>& ackedPackets,
                                    const std::vector<cc::LostPacketInfo>& lostPackets) {
    // hy2's shared cc packet-info types do not carry byte counts, so recover
    // them from the sampler's send records (equal to quic-go's BytesAcked /
    // BytesLost for tracked packets).
    std::vector<SamplerAckedPacket> acked;
    acked.reserve(ackedPackets.size());
    for (const auto& p : ackedPackets) {
        SamplerAckedPacket ap;
        ap.packetNumber = p.packetNumber;
        ap.BytesAcked = sampler_.TrackedPacketSize(p.packetNumber);
        acked.push_back(ap);
    }
    std::vector<SamplerLostPacket> lost;
    lost.reserve(lostPackets.size());
    for (const auto& p : lostPackets) {
        SamplerLostPacket lp;
        lp.packetNumber = p.packetNumber;
        lp.BytesLost = sampler_.TrackedPacketSize(p.packetNumber);
        lost.push_back(lp);
    }

    ByteCount totalBytesAckedBefore = sampler_.TotalBytesAcked();
    ByteCount totalBytesLostBefore = sampler_.TotalBytesLost();

    bool isRoundStart = false;
    bool minRttExpired = false;
    ByteCount excessAcked = 0;
    ByteCount bytesLost = 0;

    // The send state of the largest packet in ackedPackets, unless it is empty.
    // If ackedPackets is empty, it's the send state of the largest packet in
    // lostPackets.
    SendTimeState lastPacketSendState;

    MaybeAppLimited(priorInFlight);

    // Update bytesInFlight
    bytesInFlight_ = priorInFlight;
    for (const auto& p : acked) {
        bytesInFlight_ -= p.BytesAcked;
    }
    for (const auto& p : lost) {
        bytesInFlight_ -= p.BytesLost;
    }

    if (!acked.empty()) {
        PacketNumber lastAckedPacket = acked.back().packetNumber;
        isRoundStart = UpdateRoundTripCounter(lastAckedPacket);
        UpdateRecoveryState(lastAckedPacket, !lost.empty(), isRoundStart);
    }

    CongestionEventSample sample = sampler_.OnCongestionEvent(
        eventTime, acked, lost, maxBandwidth_.GetBest(), kInfBandwidth, roundTripCount_);
    if (sample.LastPacketSendState.IsValid) {
        lastSampleIsAppLimited_ = sample.LastPacketSendState.IsAppLimited;
        hasNoAppLimitedSample_ = hasNoAppLimitedSample_ || !lastSampleIsAppLimited_;
    }
    // Avoid updating |maxBandwidth_| if a) this is a loss-only event, or b) all
    // packets in |ackedPackets| did not generate valid samples. (e.g. ack of
    // ack-only packets). In both cases, sampler.TotalBytesAcked will not change.
    if (totalBytesAckedBefore != sampler_.TotalBytesAcked()) {
        if (!sample.SampleIsAppLimited ||
            sample.SampleMaxBandwidth > maxBandwidth_.GetBest()) {
            maxBandwidth_.Update(sample.SampleMaxBandwidth, roundTripCount_);
        }
    }

    if (sample.SampleRtt.ns != kInfRTT.ns) {
        minRttExpired = MaybeUpdateMinRtt(eventTime, sample.SampleRtt);
    }
    bytesLost = sampler_.TotalBytesLost() - totalBytesLostBefore;

    excessAcked = sample.ExtraAcked;
    lastPacketSendState = sample.LastPacketSendState;

    if (!lost.empty()) {
        numLossEventsInRound_++;
        bytesLostInRound_ += bytesLost;
    }

    // Handle logic specific to PROBE_BW mode.
    if (mode_ == BbrMode::kProbeBw) {
        UpdateGainCyclePhase(eventTime, priorInFlight, !lost.empty());
    }

    // Handle logic specific to STARTUP and DRAIN modes.
    if (isRoundStart && !isAtFullBandwidth_) {
        CheckIfFullBandwidthReached(lastPacketSendState);
    }

    MaybeExitStartupOrDrain(eventTime);

    // Handle logic specific to PROBE_RTT.
    MaybeEnterOrExitProbeRtt(eventTime, isRoundStart, minRttExpired);

    // Calculate number of packets acked and lost.
    ByteCount bytesAcked = sampler_.TotalBytesAcked() - totalBytesAckedBefore;

    // After the model is updated, recalculate the pacing rate and congestion
    // window.
    CalculatePacingRate(bytesLost);
    CalculateCongestionWindow(bytesAcked, excessAcked);
    CalculateRecoveryWindow(bytesAcked, bytesLost);

    // Cleanup internal state.
    // The "least unacked" should actually be FirstOutstanding, but since we are
    // not passing that through OnCongestionEventEx, we only estimate using
    // acked/lost packets (differs by no more than 2 packets due to fast
    // retransmission).
    if (!acked.empty()) {
        sampler_.RemoveObsoletePackets(acked.back().packetNumber - 2);
    } else if (!lost.empty()) {
        sampler_.RemoveObsoletePackets(lost.back().packetNumber + 1);
    }

    if (isRoundStart) {
        numLossEventsInRound_ = 0;
        bytesLostInRound_ = 0;
    }
}

Bandwidth BbrSender::PacingRate() {
    if (pacingRate_ == 0) {
        return Bandwidth(highGain_ *
            static_cast<double>(BandwidthFromDelta(initialCongestionWindow_, GetMinRtt())));
    }

    return pacingRate_;
}

Bandwidth BbrSender::BandwidthEstimate() {
    return maxBandwidth_.GetBest();
}

ByteCount BbrSender::BandwidthForPacer() {
    ByteCount bps =
        static_cast<ByteCount>(static_cast<double>(PacingRate()) /
                               static_cast<double>(kBytesPerSecond));
    if (bps < kMinBps) {
        // We need to make sure that the bandwidth value for pacer is never zero,
        // otherwise it will go into an edge case where HasPacingBudget = false
        // but TimeUntilSend is before, causing the send loop to go crazy and
        // get stuck.
        return kMinBps;
    }
    return bps;
}

Duration BbrSender::RttStatsMinRTT() const {
    return rttStats_ != nullptr ? rttStats_->MinRTT() : Duration{};
}

Duration BbrSender::GetMinRtt() {
    if (minRtt_.ns != 0) {
        return minRtt_;
    }
    Duration minRtt = RttStatsMinRTT();
    if (minRtt.ns == 0) {
        return Duration::FromMillis(100);
    }
    return minRtt;
}

ByteCount BbrSender::GetTargetCongestionWindow(double gain) {
    ByteCount bdp = BdpFromRttAndBandwidth(GetMinRtt(), BandwidthEstimate());
    ByteCount targetWindow = static_cast<ByteCount>(gain * static_cast<double>(bdp));

    // BDP estimate will be zero if no bandwidth samples are available yet.
    if (targetWindow == 0) {
        targetWindow =
            static_cast<ByteCount>(gain * static_cast<double>(initialCongestionWindow_));
    }

    return std::max(targetWindow, minCongestionWindow_);
}

ByteCount BbrSender::ProbeRttCongestionWindow() {
    return minCongestionWindow_;
}

bool BbrSender::MaybeUpdateMinRtt(MonoTime now, Duration sampleMinRtt) {
    // Do not expire min_rtt if none was ever available.
    bool minRttExpired = minRtt_.ns != 0 && now > minRttTimestamp_.Add(kMinRttExpiry.ns);
    if (minRttExpired || sampleMinRtt < minRtt_ || minRtt_.ns == 0) {
        minRtt_ = sampleMinRtt;
        minRttTimestamp_ = now;
    }

    return minRttExpired;
}

void BbrSender::EnterStartupMode(MonoTime /*now*/) {
    mode_ = BbrMode::kStartup;
    pacingGain_ = highGain_;
    congestionWindowGain_ = highCwndGain_;

    if (debug_) {
        DebugPrint("Phase: STARTUP");
    }
}

void BbrSender::EnterProbeBandwidthMode(MonoTime now) {
    mode_ = BbrMode::kProbeBw;
    congestionWindowGain_ = congestionWindowGainConstant_;

    // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
    // excluded because in that case increased gain and decreased gain would not
    // follow each other.
    cycleCurrentOffset_ =
        static_cast<int>(RandomUint32() % static_cast<std::uint32_t>(kPacketsPerConnectionID)) %
        (kGainCycleLength - 1);
    if (cycleCurrentOffset_ >= 1) {
        cycleCurrentOffset_ += 1;
    }

    lastCycleStart_ = now;
    pacingGain_ = kPacingGain[cycleCurrentOffset_];

    if (debug_) {
        DebugPrint("Phase: PROBE_BW");
    }
}

bool BbrSender::UpdateRoundTripCounter(PacketNumber lastAckedPacket) {
    if (currentRoundTripEnd_ == kInvalidPacketNumber || lastAckedPacket > currentRoundTripEnd_) {
        roundTripCount_++;
        currentRoundTripEnd_ = lastSentPacket_;
        return true;
    }
    return false;
}

void BbrSender::UpdateGainCyclePhase(MonoTime now, ByteCount priorInFlight, bool hasLosses) {
    // In most cases, the cycle is advanced after an RTT passes.
    bool shouldAdvanceGainCycling = now > lastCycleStart_.Add(GetMinRtt().ns);
    // If the pacing gain is above 1.0, the connection is trying to probe the
    // bandwidth by increasing the number of bytes in flight to at least
    // pacing_gain * BDP. Make sure that it actually reaches the target, as long
    // as there are no losses suggesting that the buffers are not able to hold
    // that much.
    if (pacingGain_ > 1.0 && !hasLosses &&
        priorInFlight < GetTargetCongestionWindow(pacingGain_)) {
        shouldAdvanceGainCycling = false;
    }

    // If pacing gain is below 1.0, the connection is trying to drain the extra
    // queue which could have been incurred by probing prior to it. If the
    // number of bytes in flight falls down to the estimated BDP value earlier,
    // conclude that the queue has been successfully drained and exit this cycle
    // early.
    if (pacingGain_ < 1.0 && bytesInFlight_ <= GetTargetCongestionWindow(1)) {
        shouldAdvanceGainCycling = true;
    }

    if (shouldAdvanceGainCycling) {
        cycleCurrentOffset_ = (cycleCurrentOffset_ + 1) % kGainCycleLength;
        lastCycleStart_ = now;
        // Stay in low gain mode until the target BDP is hit.
        // Low gain mode will be exited immediately when the target BDP is
        // achieved.
        if (drainToTarget_ && pacingGain_ < 1 &&
            kPacingGain[cycleCurrentOffset_] == 1 &&
            bytesInFlight_ > GetTargetCongestionWindow(1)) {
            return;
        }
        pacingGain_ = kPacingGain[cycleCurrentOffset_];
    }
}

void BbrSender::CheckIfFullBandwidthReached(const SendTimeState& lastPacketSendState) {
    if (lastSampleIsAppLimited_) {
        return;
    }

    Bandwidth target =
        static_cast<Bandwidth>(static_cast<double>(bandwidthAtLastRound_) * kStartupGrowthTarget);
    if (BandwidthEstimate() >= target) {
        bandwidthAtLastRound_ = BandwidthEstimate();
        roundsWithoutBandwidthGain_ = 0;
        if (expireAckAggregationInStartup_) {
            // Expire old excess delivery measurements now that bandwidth
            // increased.
            sampler_.ResetMaxAckHeightTracker(0, roundTripCount_);
        }
        return;
    }

    roundsWithoutBandwidthGain_++;
    if (roundsWithoutBandwidthGain_ >= numStartupRtts_ ||
        ShouldExitStartupDueToLoss(lastPacketSendState)) {
        isAtFullBandwidth_ = true;
    }
}

void BbrSender::MaybeAppLimited(ByteCount bytesInFlight) {
    if (bytesInFlight < GetTargetCongestionWindow(1)) {
        sampler_.OnAppLimited();
    }
}

void BbrSender::MaybeExitStartupOrDrain(MonoTime now) {
    if (mode_ == BbrMode::kStartup && isAtFullBandwidth_) {
        mode_ = BbrMode::kDrain;
        pacingGain_ = drainGain_;
        congestionWindowGain_ = highCwndGain_;

        if (debug_) {
            DebugPrint("Phase: DRAIN");
        }
    }
    if (mode_ == BbrMode::kDrain && bytesInFlight_ <= GetTargetCongestionWindow(1)) {
        EnterProbeBandwidthMode(now);
    }
}

void BbrSender::MaybeEnterOrExitProbeRtt(MonoTime now, bool isRoundStart, bool minRttExpired) {
    if (minRttExpired && !exitingQuiescence_ && mode_ != BbrMode::kProbeRtt) {
        mode_ = BbrMode::kProbeRtt;
        pacingGain_ = 1.0;
        // Do not decide on the time to exit PROBE_RTT until the
        // |bytesInFlight_| is at the target small value.
        exitProbeRttAt_ = MonoTime(0);

        if (debug_) {
            char buf[224];
            std::snprintf(buf, sizeof(buf),
                          "BandwidthEstimate: %s, CongestionWindowGain: %.2f, PacingGain: %.2f,"
                          " PacingRate: %s",
                          formatSpeed(BandwidthEstimate()).c_str(), congestionWindowGain_,
                          pacingGain_, formatSpeed(PacingRate()).c_str());
            DebugPrint(buf);
            DebugPrint("Phase: PROBE_RTT");
        }
    }

    if (mode_ == BbrMode::kProbeRtt) {
        sampler_.OnAppLimited();

        if (exitProbeRttAt_.IsZero()) {
            // If the window has reached the appropriate size, schedule exiting
            // PROBE_RTT. The CWND during PROBE_RTT is kMinimumCongestionWindow,
            // but we allow an extra packet since QUIC checks CWND before
            // sending a packet.
            if (bytesInFlight_ < ProbeRttCongestionWindow() + kMaxPacketBufferSize) {
                exitProbeRttAt_ = now.Add(kProbeRttTime.ns);
                probeRttRoundPassed_ = false;
            }
        } else {
            if (isRoundStart) {
                probeRttRoundPassed_ = true;
            }
            if (now.Sub(exitProbeRttAt_) >= 0 && probeRttRoundPassed_) {
                minRttTimestamp_ = now;
                if (debug_) {
                    char buf[64];
                    std::snprintf(buf, sizeof(buf), "MinRTT: %lldms",
                                  static_cast<long long>(GetMinRtt().Milliseconds()));
                    DebugPrint(buf);
                }
                if (!isAtFullBandwidth_) {
                    EnterStartupMode(now);
                } else {
                    EnterProbeBandwidthMode(now);
                }
            }
        }
    }

    exitingQuiescence_ = false;
}

void BbrSender::UpdateRecoveryState(PacketNumber lastAckedPacket, bool hasLosses,
                                    bool isRoundStart) {
    // Disable recovery in startup, if loss-based exit is enabled.
    if (!isAtFullBandwidth_) {
        return;
    }

    // Exit recovery when there are no losses for a round.
    if (hasLosses) {
        endRecoveryAt_ = lastSentPacket_;
    }

    switch (recoveryState_) {
    case BbrRecoveryState::kNotInRecovery:
        if (hasLosses) {
            recoveryState_ = BbrRecoveryState::kConservation;
            // This will cause the |recoveryWindow_| to be set to the correct
            // value in CalculateRecoveryWindow().
            recoveryWindow_ = 0;
            // Since the conservation phase is meant to be lasting for a whole
            // round, extend the current round as if it were started right now.
            currentRoundTripEnd_ = lastSentPacket_;
        }
        break;
    case BbrRecoveryState::kConservation:
        if (isRoundStart) {
            recoveryState_ = BbrRecoveryState::kGrowth;
        }
        [[fallthrough]];
    case BbrRecoveryState::kGrowth:
        // Exit recovery if appropriate.
        if (!hasLosses && lastAckedPacket > endRecoveryAt_) {
            recoveryState_ = BbrRecoveryState::kNotInRecovery;
        }
        break;
    }
}

void BbrSender::CalculatePacingRate(ByteCount bytesLost) {
    if (BandwidthEstimate() == 0) {
        return;
    }

    Bandwidth targetRate =
        static_cast<Bandwidth>(pacingGain_ * static_cast<double>(BandwidthEstimate()));
    if (isAtFullBandwidth_) {
        pacingRate_ = targetRate;
        return;
    }

    // Pace at the rate of initial_window / RTT as soon as RTT measurements are
    // available.
    if (pacingRate_ == 0 && RttStatsMinRTT().ns != 0) {
        pacingRate_ = BandwidthFromDelta(initialCongestionWindow_, RttStatsMinRTT());
        return;
    }

    if (detectOvershooting_) {
        bytesLostWhileDetectingOvershooting_ += bytesLost;
        // Check for overshooting with network parameters adjusted when pacing
        // rate > target_rate and loss has been detected.
        if (pacingRate_ > targetRate && bytesLostWhileDetectingOvershooting_ > 0) {
            if (hasNoAppLimitedSample_ ||
                bytesLostWhileDetectingOvershooting_ *
                        static_cast<ByteCount>(bytesLostMultiplierWhileDetectingOvershooting_) >
                    initialCongestionWindow_) {
                // We are fairly sure overshoot happens if 1) there is at least
                // one non app-limited bw sample or 2) half of IW gets lost.
                // Slow pacing rate.
                pacingRate_ = std::max(
                    targetRate,
                    static_cast<Bandwidth>(
                        BandwidthFromDelta(cwndToCalculateMinPacingRate_, RttStatsMinRTT())));
                bytesLostWhileDetectingOvershooting_ = 0;
                detectOvershooting_ = false;
            }
        }
    }

    // Do not decrease the pacing rate during startup.
    pacingRate_ = std::max(pacingRate_, targetRate);
}

void BbrSender::CalculateCongestionWindow(ByteCount bytesAcked, ByteCount excessAcked) {
    if (mode_ == BbrMode::kProbeRtt) {
        return;
    }

    ByteCount targetWindow = GetTargetCongestionWindow(congestionWindowGain_);
    if (isAtFullBandwidth_) {
        // Add the max recently measured ack aggregation to CWND.
        targetWindow += sampler_.MaxAckHeight();
    } else if (enableAckAggregationDuringStartup_) {
        // Add the most recent excess acked. Because CWND never decreases in
        // STARTUP, this will automatically create a very localized max filter.
        targetWindow += excessAcked;
    }

    // Instead of immediately setting the target CWND as the new one, BBR grows
    // the CWND towards |targetWindow| by only increasing it |bytesAcked| at a
    // time.
    if (isAtFullBandwidth_) {
        congestionWindow_ = std::min(targetWindow, congestionWindow_ + bytesAcked);
    } else if (congestionWindow_ < targetWindow ||
               sampler_.TotalBytesAcked() < initialCongestionWindow_) {
        // If the connection is not yet out of startup phase, do not decrease
        // the window.
        congestionWindow_ += bytesAcked;
    }

    // Enforce the limits on the congestion window.
    congestionWindow_ = std::max(congestionWindow_, minCongestionWindow_);
    congestionWindow_ = std::min(congestionWindow_, maxCongestionWindow_);
}

void BbrSender::CalculateRecoveryWindow(ByteCount bytesAcked, ByteCount bytesLost) {
    if (recoveryState_ == BbrRecoveryState::kNotInRecovery) {
        return;
    }

    // Set up the initial recovery window.
    if (recoveryWindow_ == 0) {
        recoveryWindow_ = bytesInFlight_ + bytesAcked;
        recoveryWindow_ = std::max(minCongestionWindow_, recoveryWindow_);
        return;
    }

    // Remove losses from the recovery window, while accounting for a potential
    // integer underflow.
    if (recoveryWindow_ >= bytesLost) {
        recoveryWindow_ = recoveryWindow_ - bytesLost;
    } else {
        recoveryWindow_ = maxDatagramSize_;
    }

    // In CONSERVATION mode, just subtracting losses is sufficient. In GROWTH,
    // release additional |bytesAcked| to achieve a slow-start-like behavior.
    if (recoveryState_ == BbrRecoveryState::kGrowth) {
        recoveryWindow_ += bytesAcked;
    }

    // Always allow sending at least |bytesAcked| in response.
    recoveryWindow_ = std::max(recoveryWindow_, bytesInFlight_ + bytesAcked);
    recoveryWindow_ = std::max(minCongestionWindow_, recoveryWindow_);
}

bool BbrSender::ShouldExitStartupDueToLoss(const SendTimeState& lastPacketSendState) {
    if (numLossEventsInRound_ <
            static_cast<std::uint64_t>(kDefaultStartupFullLossCount) ||
        !lastPacketSendState.IsValid) {
        return false;
    }

    ByteCount inflightAtSend = lastPacketSendState.BytesInFlight;

    if (inflightAtSend > 0 && bytesLostInRound_ > 0) {
        ByteCount threshold = static_cast<ByteCount>(static_cast<double>(inflightAtSend) *
                                                     kQuicBbr2DefaultLossThreshold);
        return bytesLostInRound_ > threshold;
    }
    return false;
}

void BbrSender::DebugPrint(const std::string& message) {
    std::printf("[BBRSender] [%s] %s\n", hhmmssNow().c_str(), message.c_str());
}

std::shared_ptr<cc::CongestionControl> NewBbrSender(Clock& clock,
                                                    ByteCount initialCongestionWindow,
                                                    const Profile& profile) {
    // Mirrors Go's NewBbrSender(clock, initialMaxDatagramSize, profile): the
    // second parameter seeds the datagram size; the actual windows derive from
    // it.
    return std::make_shared<BbrSender>(clock, initialCongestionWindow,
                                       kInitialCongestionWindowPackets * initialCongestionWindow,
                                       kMaxCongestionWindowPackets * initialCongestionWindow,
                                       profile);
}

ByteCount GetInitialPacketSize(const std::string& remoteAddr) {
    // If this does not look like a UDP address, we don't know anything about
    // the MTU. Use the minimum size of an Initial packet as the max packet size.
    if (looksLikeUdpAddress(remoteAddr)) {
        return kInitialPacketSize;
    }
    return kMinInitialPacketSize;
}

} // namespace hy2::bbr
