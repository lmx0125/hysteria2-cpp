// bbr_test.cpp - port of core/internal/congestion/bbr/bbr_sender_test.go plus
// deterministic sampler/startup tests.
#include "hytest.hpp"

#include <memory>
#include <string>
#include <vector>

#include "hy2/bbr.hpp"
#include "hy2/bbr/bandwidth_sampler.hpp"
#include "hy2/bbr/bbr_sender.hpp"
#include "hy2/error.hpp"

namespace {

using hy2::ByteCount;
using hy2::Duration;
using hy2::MonoTime;
using hy2::PacketNumber;
using hy2::bbr::Bandwidth;

class FakeClock : public hy2::bbr::Clock {
public:
    explicit FakeClock(MonoTime start) : now_(start) {}
    MonoTime Now() override { return now_; }
    void AdvanceNs(std::int64_t ns) { now_ = MonoTime(now_.ns + ns); }

private:
    MonoTime now_;
};

class FakeRTTStats : public hy2::cc::RTTStatsProvider {
public:
    explicit FakeRTTStats(Duration rtt) : rtt_(rtt) {}
    Duration MinRTT() const override { return rtt_; }
    Duration LatestRTT() const override { return rtt_; }
    Duration SmoothedRTT() const override { return rtt_; }
    Duration MeanDeviation() const override { return Duration(0); }

private:
    Duration rtt_;
};

} // namespace

// Port of TestSetMaxDatagramSizeRescalesPacketSizedWindows.
HY_TEST(BbrSetMaxDatagramSizeRescalesPacketSizedWindows) {
    const ByteCount oldMaxDatagramSize = 1000;
    const ByteCount newMaxDatagramSize = 1400;
    const ByteCount initialCongestionWindowPackets = 20;
    const ByteCount maxCongestionWindowPackets = 80;

    FakeClock clock(MonoTime(1000000000));
    hy2::bbr::BbrSender b(clock, oldMaxDatagramSize,
                          initialCongestionWindowPackets * oldMaxDatagramSize,
                          maxCongestionWindowPackets * oldMaxDatagramSize,
                          hy2::bbr::ProfileStandard);

    HY_CHECK_EQ(b.GetCongestionWindow(),
                initialCongestionWindowPackets * oldMaxDatagramSize);

    b.SetMaxDatagramSize(newMaxDatagramSize);

    HY_CHECK_EQ(b.InitialCongestionWindowBytes(),
                initialCongestionWindowPackets * newMaxDatagramSize);
    HY_CHECK_EQ(b.MaxCongestionWindowBytes(), maxCongestionWindowPackets * newMaxDatagramSize);
    HY_CHECK_EQ(b.MinCongestionWindowBytes(), 4 * newMaxDatagramSize);
    HY_CHECK_EQ(b.GetCongestionWindow(), initialCongestionWindowPackets * newMaxDatagramSize);
}

// Port of TestSetMaxDatagramSizeClampsCongestionWindow.
HY_TEST(BbrSetMaxDatagramSizeClampsCongestionWindow) {
    const ByteCount oldMaxDatagramSize = 1000;
    const ByteCount newMaxDatagramSize = 1400;

    FakeClock clock(MonoTime(1000000000));
    hy2::bbr::BbrSender b(clock, oldMaxDatagramSize,
                          32 * oldMaxDatagramSize,
                          hy2::bbr::kMaxCongestionWindowPackets * oldMaxDatagramSize,
                          hy2::bbr::ProfileStandard);
    b.SetCongestionWindowForTest(b.MinCongestionWindowBytes() + oldMaxDatagramSize);
    b.SetRecoveryWindowForTest(b.MinCongestionWindowBytes() + oldMaxDatagramSize);

    b.SetMaxDatagramSize(newMaxDatagramSize);

    HY_CHECK_EQ(b.GetCongestionWindow(), b.MinCongestionWindowBytes());
    HY_CHECK_EQ(b.RecoveryWindowBytes(), b.MinCongestionWindowBytes());
}

// Port of TestNewBbrSenderAppliesProfiles.
HY_TEST(BbrNewBbrSenderAppliesProfiles) {
    struct Case {
        const char* name;
        const char* profile;
        double highGain;
        double highCwndGain;
        double congestionWindowGainConstant;
        std::int64_t numStartupRtts;
        bool drainToTarget;
        bool detectOvershooting;
        std::uint8_t bytesLostMultiplier;
        bool enableAckAggregationDuringStartup;
        bool expireAckAggregationInStartup;
        bool enableOverestimateAvoidance;
        bool reduceExtraAckedOnBandwidthIncrease;
    };
    const Case cases[] = {
        {"standard", "standard",
         2.885, 2.0, 2.0, 3, false, false, 2, false, false, false, false},
        {"conservative", "conservative",
         2.25, 1.75, 1.75, 2, true, true, 1, false, false, true, true},
        {"aggressive", "aggressive",
         3.0, 2.25, 2.5, 4, false, false, 2, true, true, false, false},
    };

    for (const auto& tc : cases) {
        FakeClock clock(MonoTime(1000000000));
        hy2::bbr::BbrSender b(clock, hy2::kInitialPacketSize,
                              32 * hy2::kInitialPacketSize,
                              hy2::bbr::kMaxCongestionWindowPackets * hy2::kInitialPacketSize,
                              hy2::bbr::Profile(tc.profile));
        std::printf("profile case: %s\n", tc.name);
        HY_CHECK_EQ(b.ProfileName(), std::string(tc.profile));
        HY_CHECK_NEAR(b.HighGainValue(), tc.highGain, 1e-12);
        HY_CHECK_NEAR(b.HighCwndGainValue(), tc.highCwndGain, 1e-12);
        HY_CHECK_NEAR(b.CongestionWindowGainConstantValue(), tc.congestionWindowGainConstant, 1e-12);
        HY_CHECK_EQ(b.NumStartupRttsValue(), tc.numStartupRtts);
        HY_CHECK_EQ(b.DrainToTargetEnabled(), tc.drainToTarget);
        HY_CHECK_EQ(b.DetectOvershootingEnabled(), tc.detectOvershooting);
        HY_CHECK_EQ(b.BytesLostMultiplierValue(), tc.bytesLostMultiplier);
        HY_CHECK_EQ(b.AckAggregationDuringStartupEnabled(), tc.enableAckAggregationDuringStartup);
        HY_CHECK_EQ(b.ExpireAckAggregationInStartupEnabled(), tc.expireAckAggregationInStartup);
        HY_CHECK_EQ(b.OverestimateAvoidanceEnabled(), tc.enableOverestimateAvoidance);
        HY_CHECK_EQ(b.ReduceExtraAckedOnBandwidthIncreaseEnabled(),
                    tc.reduceExtraAckedOnBandwidthIncrease);
        // enterStartupMode applied the profile gains.
        HY_CHECK_NEAR(b.PacingGainValue(), b.HighGainValue(), 1e-12);
        HY_CHECK_NEAR(b.CongestionWindowGainValue(), b.HighCwndGainValue(), 1e-12);
    }
}

// Port of TestParseProfile.
HY_TEST(BbrParseProfile) {
    HY_CHECK_EQ(hy2::bbr::ParseProfile(""), std::string("standard"));
    HY_CHECK_EQ(hy2::bbr::ParseProfile("Aggressive"), std::string("aggressive"));

    bool threw = false;
    try {
        (void)hy2::bbr::ParseProfile("turbo");
    } catch (const hy2::Error& e) {
        threw = true;
        HY_CHECK_EQ(std::string(e.what()), std::string("unsupported BBR profile \"turbo\""));
    }
    HY_CHECK(threw);
}

HY_TEST(BbrGetInitialPacketSize) {
    // UDP-address-like strings map to congestion.InitialPacketSize...
    HY_CHECK_EQ(hy2::bbr::GetInitialPacketSize("1.2.3.4:443"), hy2::kInitialPacketSize);
    HY_CHECK_EQ(hy2::bbr::GetInitialPacketSize("[2001:db8::1]:443"), hy2::kInitialPacketSize);
    // ...anything else maps to the minimum Initial packet size.
    HY_CHECK_EQ(hy2::bbr::GetInitialPacketSize(""), hy2::bbr::kMinInitialPacketSize);
    HY_CHECK_EQ(hy2::bbr::GetInitialPacketSize("1.2.3.4"), hy2::bbr::kMinInitialPacketSize);
    HY_CHECK_EQ(hy2::bbr::GetInitialPacketSize("example.com"), hy2::bbr::kMinInitialPacketSize);
    HY_CHECK_EQ(hy2::bbr::GetInitialPacketSize("[::1]"), hy2::bbr::kMinInitialPacketSize);
}

// Deterministic bandwidth sampler basics: two packets sent, second acked.
HY_TEST(BandwidthSamplerBasics) {
    const ByteCount S = 1350;
    const std::int64_t ms = 1000000;

    hy2::bbr::BandwidthSampler sampler(10);

    MonoTime t0(1000 * ms);
    sampler.OnPacketSent(t0, /*packetNumber=*/1, S, /*bytesInFlight=*/0, /*isRetransmittable=*/true);
    MonoTime t1 = t0.Add(5 * ms);
    sampler.OnPacketSent(t1, /*packetNumber=*/2, S, /*bytesInFlight=*/S, /*isRetransmittable=*/true);

    std::vector<hy2::bbr::SamplerAckedPacket> acked{{2, S}};
    MonoTime t2 = t1.Add(20 * ms);
    hy2::bbr::CongestionEventSample sample =
        sampler.OnCongestionEvent(t2, acked, {}, /*maxBandwidth=*/0,
                                  hy2::bbr::kInfBandwidth, /*roundTripCount=*/1);

    HY_CHECK_EQ(sampler.TotalBytesSent(), 2 * S);
    HY_CHECK_EQ(sampler.TotalBytesAcked(), S);
    HY_CHECK_EQ(sampler.TrackedPacketSize(2), S);
    // ackRate = S*8/(25ms); sendRate = S*8/(5ms); sample is their minimum.
    Bandwidth expectedAckRate = hy2::bbr::BandwidthFromDelta(S, Duration(25 * ms));
    Bandwidth expectedSendRate = hy2::bbr::BandwidthFromDelta(S, Duration(5 * ms));
    HY_CHECK_EQ(expectedSendRate, static_cast<Bandwidth>(2160000));
    HY_CHECK_EQ(expectedAckRate, static_cast<Bandwidth>(432000));
    HY_CHECK_EQ(sample.SampleMaxBandwidth, std::min(expectedSendRate, expectedAckRate));
    HY_CHECK_EQ(sample.SampleRtt.ns, 20 * ms);
    HY_CHECK_EQ(sample.ExtraAcked, 0);
    HY_CHECK(sample.LastPacketSendState.IsValid);
    HY_CHECK(!sample.LastPacketSendState.IsAppLimited);
    HY_CHECK(!sample.SampleIsAppLimited);
    // Send-time inflight includes the acked packet itself.
    HY_CHECK_EQ(sample.LastPacketSendState.BytesInFlight, 2 * S);

    // Loss path: packet 1 is still tracked and reports its send-time state.
    hy2::bbr::SendTimeState lostState = sampler.OnPacketLost(1, S);
    HY_CHECK(lostState.IsValid);
    HY_CHECK_EQ(sampler.TotalBytesLost(), S);
    HY_CHECK_EQ(lostState.BytesInFlight, S);

    HY_CHECK_EQ(sampler.MaxAckHeight(), 0); // first epoch only records the start
}

// Deterministic end-to-end sanity check: synthetic sends/acks drive the sender
// through STARTUP (cwnd growth), then three flat rounds exit STARTUP into
// DRAIN/PROBE_BW.
HY_TEST(BbrStartupGrowthThenExit) {
    FakeClock clock(MonoTime(1000000000)); // 1 s
    FakeRTTStats rtt(Duration::FromMillis(20));

    const ByteCount S = 1350;
    const ByteCount initCwnd = 32 * S;
    hy2::bbr::BbrSender sender(clock, S, initCwnd,
                               hy2::bbr::kMaxCongestionWindowPackets * S,
                               hy2::bbr::ProfileStandard);
    sender.SetRTTStatsProvider(&rtt);

    HY_CHECK(sender.InSlowStart());
    HY_CHECK_EQ(sender.GetCongestionWindow(), initCwnd);
    HY_CHECK(!sender.InRecovery());

    const std::int64_t rttNs = 20000000; // 20 ms
    const std::int64_t dt = 20000;       // 20 us between sends within a round
    std::int64_t t = clock.Now().ns;
    PacketNumber pn = 0;

    for (int round = 0; round < 8; round++) {
        // Rounds 0-4 triple the per-round volume (bandwidth grows ~3x per
        // round); rounds 5-7 keep it constant so startup growth stalls.
        int K = 64;
        for (int i = 0; i < round && i < 5; i++) K *= 3;

        std::vector<hy2::cc::AckedPacketInfo> acked;
        acked.reserve(static_cast<std::size_t>(K));
        for (int i = 0; i < K; i++) {
            t += dt;
            sender.OnPacketSent(MonoTime(t), static_cast<ByteCount>(i) * S, pn, S, true);
            acked.push_back(hy2::cc::AckedPacketInfo{pn, MonoTime(t + rttNs)});
            pn++;
        }
        t += rttNs;
        clock.AdvanceNs(t - clock.Now().ns);
        sender.OnCongestionEventEx(static_cast<ByteCount>(K) * S, MonoTime(t), acked, {});

        if (round == 1) {
            // Still in STARTUP, but cwnd must have grown beyond the IW.
            HY_CHECK(sender.InSlowStart());
            HY_CHECK(sender.GetCongestionWindow() > initCwnd);
        }
    }

    // After three rounds without bandwidth growth, full bandwidth was reached:
    // no longer slow start, and cwnd grew well past its initial value.
    HY_CHECK(!sender.InSlowStart());
    HY_CHECK(sender.IsAtFullBandwidth());
    HY_CHECK(sender.GetCongestionWindow() > initCwnd);
    HY_CHECK(sender.PacingRate() > 0);
}
