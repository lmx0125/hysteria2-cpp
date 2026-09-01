// congestion_bench.cpp - Microbenchmarks for BBR, Brutal, and Pacer.
// Tests pure computational overhead of congestion control decisions
// without any real network I/O.
#include "bench.hpp"

#include "hy2/brutal.hpp"
#include "hy2/bbr/bbr_sender.hpp"
#include "hy2/pacer.hpp"
#include "hy2/common.hpp"

#include <algorithm>
#include <vector>

using namespace hy2;
using namespace hy2::cc;

// ---------------------------------------------------------------------------
// Fake RTT stats provider for standalone congestion control benchmarks
// ---------------------------------------------------------------------------
namespace {
class FakeRTTStats : public RTTStatsProvider {
public:
    Duration MinRTT() const override { return Duration::FromMillis(10); }
    Duration LatestRTT() const override { return Duration::FromMillis(12); }
    Duration SmoothedRTT() const override { return Duration::FromMillis(11); }
    Duration MeanDeviation() const override { return Duration::FromMillis(2); }
};
} // namespace

// ---------------------------------------------------------------------------
// Brutal sender benchmarks
// ---------------------------------------------------------------------------

HY_BENCH(brutal_create_100mbps, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(100000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);
    (void)sender.GetCongestionWindow();
}

HY_BENCH(brutal_create_1gbps, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);
    (void)sender.GetCongestionWindow();
}

HY_BENCH(brutal_create_10gbps, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(10000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);
    (void)sender.GetCongestionWindow();
}

// Simulate send-ack cycle at 1 Gbps
HY_BENCH(brutal_send_ack_cycle_1gbps, 1200) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    for (int i = 0; i < 100; ++i) {
        sender.OnPacketSent(now, i * 1200, i, 1200, false);
        now = now.Add(1000000); // +1ms
        std::vector<AckedPacketInfo> acked = {{i, now}};
        std::vector<LostPacketInfo> lost;
        sender.OnCongestionEventEx(i * 1200, now, acked, lost);
    }
    (void)sender.GetCongestionWindow();
}

// TimeUntilSend decision (the hot path in real usage)
HY_BENCH(brutal_time_until_send, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    for (int i = 0; i < 1000; ++i) {
        (void)sender.TimeUntilSend(i * 1200);
        now = now.Add(100000);
    }
}

// HasPacingBudget (frequently called in hot path)
HY_BENCH(brutal_has_pacing_budget, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    for (int i = 0; i < 500; ++i) {
        (void)sender.HasPacingBudget(now);
        now = now.Add(100000); // 100us
    }
}

// CanSend (called per packet)
HY_BENCH(brutal_can_send, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    for (int i = 0; i < 500; ++i) {
        (void)sender.CanSend(i * 1200);
    }
}

// GetCongestionWindow (called per packet)
HY_BENCH(brutal_get_cwnd, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    for (int i = 0; i < 500; ++i) {
        (void)sender.GetCongestionWindow();
    }
}

// Loss compensation: OnCongestionEventEx with 20% loss
HY_BENCH(brutal_loss_compensation_20pct, 1200) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    std::vector<AckedPacketInfo> acked;
    std::vector<LostPacketInfo> lost;
    for (int i = 0; i < 100; ++i) {
        if (i % 5 == 0) {
            lost.push_back({i, now});
        } else {
            acked.push_back({i, now});
        }
    }
    sender.OnCongestionEventEx(0, now, acked, lost);
    (void)sender.AckRate();
}

// ---------------------------------------------------------------------------
// Pacer benchmarks
// ---------------------------------------------------------------------------

HY_BENCH(pacer_budget_calculation, 0) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    // Create a pacer through the brutal sender's internal state
    // We benchmark TimeUntilSend which internally calls the pacer
    MonoTime now = MonoTime::Now();
    for (int i = 0; i < 10000; ++i) {
        (void)sender.TimeUntilSend((i % 100) * 1200);
        now = now.Add(100000); // 100us
    }
}

// Simulate rapid burst of 10 packets (max burst)
HY_BENCH(pacer_burst_10_packets, 1200) {
    FakeRTTStats rtt;
    BrutalSender sender(1000000000ULL, false);
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    for (int i = 0; i < 10; ++i) {
        sender.OnPacketSent(now, i * 1200, i, 1200, false);
    }
    // Now check pacing budget is exhausted
    (void)sender.HasPacingBudget(now);
}

// ---------------------------------------------------------------------------
// BBR sender benchmarks
// ---------------------------------------------------------------------------
namespace {
class SimpleClock : public bbr::Clock {
public:
    MonoTime Now() override { return MonoTime::Now(); }
};

class SimpleRTTStats : public RTTStatsProvider {
public:
    Duration MinRTT() const override { return Duration::FromMillis(5); }
    Duration LatestRTT() const override { return Duration::FromMillis(8); }
    Duration SmoothedRTT() const override { return Duration::FromMillis(7); }
    Duration MeanDeviation() const override { return Duration::FromMillis(1); }
};
} // namespace

HY_BENCH(bbr_create_standard, 0) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileStandard);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);
}

HY_BENCH(bbr_create_conservative, 0) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileConservative);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);
}

HY_BENCH(bbr_create_aggressive, 0) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileAggressive);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);
}

// Simulate BBR startup phase: send + ack loop
HY_BENCH(bbr_startup_send_ack_loop, 1200) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileStandard);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    PacketNumber pn = 0;
    ByteCount inFlight = 0;

    // Send 100 packets with acks (simulating startup)
    for (int i = 0; i < 100; ++i) {
        if (sender.CanSend(inFlight) && sender.HasPacingBudget(now)) {
            sender.OnPacketSent(now, inFlight, pn, 1200, false);
            inFlight += 1200;
            pn++;

            // Simulate ack after 8ms RTT
            now = now.Add(8000000);
            std::vector<AckedPacketInfo> acked = {{pn - 1, now}};
            std::vector<LostPacketInfo> lost;
            sender.OnCongestionEventEx(inFlight, now, acked, lost);
            inFlight -= 1200;
        }
        now = now.Add(100000); // 100us between packets
    }
    (void)sender.GetCongestionWindow();
}

// BBR TimeUntilSend (hot path)
HY_BENCH(bbr_time_until_send, 0) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileStandard);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    for (int i = 0; i < 500; ++i) {
        (void)sender.TimeUntilSend((i % 200) * 1200);
    }
}

// BBR HasPacingBudget (hot path)
HY_BENCH(bbr_has_pacing_budget, 0) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileStandard);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    for (int i = 0; i < 500; ++i) {
        (void)sender.HasPacingBudget(now);
        now = now.Add(100000); // 100us
    }
}

// BBR GetCongestionWindow (hot path)
HY_BENCH(bbr_get_cwnd, 0) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileStandard);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);

    for (int i = 0; i < 500; ++i) {
        (void)sender.GetCongestionWindow();
    }
}

// BBR PacingRate calculation
HY_BENCH(bbr_pacing_rate, 0) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileStandard);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);

    for (int i = 0; i < 500; ++i) {
        (void)sender.PacingRate();
    }
}

// BBR full send-ack-drive cycle (realistic hot path)
HY_BENCH(bbr_full_cycle_1000pkts, 1200) {
    SimpleClock clock;
    bbr::BbrSender sender(clock, 1200, 1200 * 32, 1200 * 20000,
                          bbr::ProfileStandard);
    SimpleRTTStats rtt;
    sender.SetRTTStatsProvider(&rtt);

    MonoTime now = MonoTime::Now();
    PacketNumber pn = 0;
    ByteCount inFlight = 0;
    int sent = 0;

    while (sent < 1000) {
        if (sender.CanSend(inFlight) && sender.HasPacingBudget(now)) {
            sender.OnPacketSent(now, inFlight, pn, 1200, false);
            inFlight += 1200;
            pn++;
            sent++;

            // Every 10 packets, simulate ack batch
            if (sent % 10 == 0) {
                now = now.Add(8000000); // 8ms RTT
                std::vector<AckedPacketInfo> acked;
                for (int j = 0; j < 10; ++j) {
                    acked.push_back({pn - 10 + j, now});
                }
                std::vector<LostPacketInfo> lost;
                sender.OnCongestionEventEx(inFlight, now, acked, lost);
                inFlight -= 12000;
            }
        }
        now = now.Add(50000); // 50us between send opportunities
    }
    (void)sender.GetCongestionWindow();
    (void)sender.PacingRate();
}
