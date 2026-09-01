// brutal_pacer_test.cpp - Tests for Pacer and BrutalSender
// (ports of brutal_test.go + pacer behavior checks).
#include "hytest.hpp"

#include <vector>

#include "hy2/brutal.hpp"
#include "hy2/pacer.hpp"

using namespace hy2;
using namespace hy2::cc;

namespace {
class FakeRTTStats : public RTTStatsProvider {
public:
    Duration MinRTT() const override { return rtt_; }
    Duration LatestRTT() const override { return rtt_; }
    Duration SmoothedRTT() const override { return rtt_; }
    Duration MeanDeviation() const override { return Duration(0); }
    Duration rtt_ = Duration::FromMillis(50);
};
} // namespace

HY_TEST(PacerInitialBudgetAllowsBurst)
{
    Pacer p([] { return (ByteCount)1200 * 1000; }); // 1.2 MB/s
    MonoTime t0 = MonoTime::Now();
    // initial budget = maxBurstPackets * InitialPacketSize = 10*1350
    HY_CHECK(p.Budget(t0) >= 10 * kInitialPacketSize);
    HY_CHECK(p.TimeUntilSend().IsZero()); // can send immediately
}

HY_TEST(PacerSentPacketReducesBudget)
{
    int64_t bw = 1350 * 100; // 100 packets/s
    Pacer p([&] { return (ByteCount)bw; });
    MonoTime t0(1000000000LL); // fixed time, 1s
    p.SentPacket(t0, 13500);   // sent 10 packets worth
    ByteCount budget = p.Budget(t0);
    HY_CHECK_EQ(budget, (ByteCount)(10 * kInitialPacketSize - 13500));
    // next send must be delayed
    MonoTime when = p.TimeUntilSend();
    HY_CHECK(!when.IsZero());
    HY_CHECK(when > t0);
}

HY_TEST(PacerRefillsOverTime)
{
    int64_t bw = 1350 * 100; // 100 packets/s => 13.5ms per packet
    Pacer p([&] { return (ByteCount)bw; });
    MonoTime t0(2000000000LL);
    p.SentPacket(t0, 13500); // drain burst
    HY_CHECK(p.Budget(t0) < kInitialPacketSize);
    // after 1 second we should have a full burst again
    MonoTime t1 = t0.Add(Duration::FromSeconds(1).ns);
    HY_CHECK(p.Budget(t1) >= 10 * kInitialPacketSize);
    // and can send immediately
    HY_CHECK(p.TimeUntilSend().IsZero() || p.TimeUntilSend() <= t1);
}

HY_TEST(PacerMaxDatagramSizeChange)
{
    Pacer p([] { return (ByteCount)1000000; });
    p.SetMaxDatagramSize(1400);
    MonoTime now = MonoTime::Now();
    // HasPacingBudget-like check via Budget
    HY_CHECK(p.Budget(now) >= 1400);
}

HY_TEST(BrutalSenderCwnd)
{
    FakeRTTStats rtt;
    BrutalSender b(1024 * 1024, false); // 1 MB/s
    b.SetRTTStatsProvider(&rtt);

    // cwnd = bps * srtt * 2 / ackRate(=1)
    ByteCount expect =
        (ByteCount)((double)(1024 * 1024) * 0.05 * kCongestionWindowMultiplier / 1.0);
    HY_CHECK_EQ(b.GetCongestionWindow(), expect);

    // zero RTT fallback
    rtt.rtt_ = Duration(0);
    HY_CHECK_EQ(b.GetCongestionWindow(), (ByteCount)10240);
}

HY_TEST(BrutalSenderAckRateSampling)
{
    FakeRTTStats rtt;
    BrutalSender b(1024 * 1024, false);
    b.SetRTTStatsProvider(&rtt);

    auto base = MonoTime(1000000000000LL); // some base second
    // feed 5 seconds of samples: 90 acks + 10 losses per second => rate 0.9
    for (int64_t sec = 0; sec < 5; sec++) {
        std::vector<AckedPacketInfo> acks(sec == 4 ? 90 : 0);
        std::vector<LostPacketInfo> losses(sec == 4 ? 10 : 0);
        if (sec == 4) {
            for (int i = 0; i < 90; i++) acks[i].packetNumber = i;
            for (int i = 0; i < 10; i++) losses[i].packetNumber = 1000 + i;
        }
        b.OnCongestionEventEx(0, base.Add(Duration::FromSeconds(sec).ns), acks, losses);
    }
    // total 100 samples >= minSampleCount(50); rate 0.9 >= 0.8
    HY_CHECK_NEAR(b.AckRate(), 0.9, 0.0001);

    // low rate clamped to 0.8: new window of seconds with 50% loss
    for (int64_t sec = 5; sec < 10; sec++) {
        std::vector<AckedPacketInfo> acks(50);
        std::vector<LostPacketInfo> losses(50);
        for (int i = 0; i < 50; i++) {
            acks[i].packetNumber = 2000 + i;
            losses[i].packetNumber = 3000 + i;
        }
        b.OnCongestionEventEx(0, base.Add(Duration::FromSeconds(sec).ns), acks, losses);
    }
    HY_CHECK_NEAR(b.AckRate(), 0.8, 0.0001);

    // disableLossCompensation forces rate 1
    BrutalSender b2(1024 * 1024, true);
    b2.SetRTTStatsProvider(&rtt);
    for (int64_t sec = 20; sec < 25; sec++) {
        std::vector<AckedPacketInfo> acks(10);
        std::vector<LostPacketInfo> losses(90);
        b2.OnCongestionEventEx(0, base.Add(Duration::FromSeconds(sec).ns), acks, losses);
    }
    HY_CHECK_NEAR(b2.AckRate(), 1.0, 0.0001);
}

HY_TEST(BrutalSenderInsufficientSamples)
{
    FakeRTTStats rtt;
    BrutalSender b(1024 * 1024, false);
    b.SetRTTStatsProvider(&rtt);

    auto base = MonoTime(5000000000000LL);
    std::vector<AckedPacketInfo> acks(30);
    std::vector<LostPacketInfo> losses(19); // 49 total < 50
    b.OnCongestionEventEx(0, base, acks, losses);
    HY_CHECK_NEAR(b.AckRate(), 1.0, 0.0001);
}

HY_TEST(BrutalSenderPacingIntegration)
{
    FakeRTTStats rtt;
    BrutalSender b(1350 * 1000, false); // 1000 pkt/s
    b.SetRTTStatsProvider(&rtt);

    MonoTime now(10000000000LL);
    HY_CHECK(b.HasPacingBudget(now));
    // send a big burst to exhaust the budget
    for (int i = 0; i < 15; i++) {
        b.OnPacketSent(now, 0, i, kInitialPacketSize, true);
        b.OnCongestionEventEx(
            0, now,
            std::vector<AckedPacketInfo>{AckedPacketInfo{i, now}},
            std::vector<LostPacketInfo>{});
    }
    // after sending 15 packets the pacer budget is exhausted
    HY_CHECK(!b.HasPacingBudget(now));
}
