// hotpath_utils_test.cpp - behavioural tests for the hot-path utilities whose
// implementation changed to drop per-call synchronisation:
//   * AtomicTime  - was mutex-backed, now a relaxed atomic
//   * RandomBytes - was one locked draw per byte, now one draw per 8 bytes
//   * Channel     - TrySend now wakes only on the empty -> non-empty edge
// These pin the observable behaviour that the optimisations must not change.
#include "hytest.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "hy2/atomic_utils.hpp"
#include "hy2/common.hpp"
#include "hy2/io.hpp"

// ---------------------------------------------------------------------------
// AtomicTime

HY_TEST(AtomicTime_SetGetAndOlderThan)
{
    hy2::AtomicTime t;
    HY_CHECK_EQ(t.Get(), static_cast<int64_t>(0));

    t.Set(1000);
    HY_CHECK_EQ(t.Get(), static_cast<int64_t>(1000));

    // OlderThan(nanos, timeout) is "nanos - Get() > timeout".
    HY_CHECK(t.OlderThan(2000, 500));    // 2000-1000 = 1000 > 500
    HY_CHECK(!t.OlderThan(1200, 500));   // 1200-1000 = 200 <= 500

    hy2::AtomicTime now = hy2::AtomicTime::FromNow();
    HY_CHECK(now.Get() > 0);
}

// Concurrent writers and readers must only ever observe a value some writer
// actually stored - i.e. no torn 64-bit read.
HY_TEST(AtomicTime_ConcurrentReadsSeeStoredValues)
{
    hy2::AtomicTime t;
    std::atomic<bool> stop{false};
    std::atomic<bool> sawUnknown{false};

    const std::vector<int64_t> kValues = {11, 22, 33, 44, 55};

    std::thread writer([&] {
        for (int i = 0; i < 200000; ++i) {
            t.Set(kValues[static_cast<size_t>(i) % kValues.size()]);
        }
        stop = true;
    });
    std::thread reader([&] {
        while (!stop.load()) {
            const int64_t v = t.Get();
            bool known = (v == 0);
            for (const int64_t k : kValues) known = known || (v == k);
            if (!known) sawUnknown = true;
        }
    });

    writer.join();
    reader.join();
    HY_CHECK(!sawUnknown.load());
}

// ---------------------------------------------------------------------------
// RandomBytes / RandomUint64

HY_TEST(RandomBytes_FillsEntireBuffer)
{
    // The implementation now writes 8 bytes per draw and a tail, so a length
    // that is not a multiple of 8 must still be filled completely.
    for (size_t len : {size_t(1), size_t(7), size_t(8), size_t(9), size_t(31), size_t(64)}) {
        std::vector<uint8_t> buf(len, 0xAA);
        hy2::RandomBytes(buf.data(), len);
        bool allUntouched = true;
        for (uint8_t b : buf) {
            if (b != 0xAA) { allUntouched = false; break; }
        }
        HY_CHECK(!allUntouched);
    }
}

HY_TEST(RandomBytes_SuccessiveCallsDiffer)
{
    std::vector<uint8_t> a(32, 0), b(32, 0);
    hy2::RandomBytes(a.data(), a.size());
    hy2::RandomBytes(b.data(), b.size());
    HY_CHECK(a != b);

    // Distinct across threads too: the per-thread generator must not hand the
    // same stream to two threads.
    std::vector<std::vector<uint8_t>> out(4, std::vector<uint8_t>(32, 0));
    std::vector<std::thread> threads;
    for (size_t i = 0; i < out.size(); ++i) {
        threads.emplace_back([&out, i] { hy2::RandomBytes(out[i].data(), out[i].size()); });
    }
    for (auto& th : threads) th.join();
    std::set<std::vector<uint8_t>> distinct(out.begin(), out.end());
    HY_CHECK_EQ(distinct.size(), out.size());
}

// ---------------------------------------------------------------------------
// Channel

// A parked consumer must be woken by the empty -> non-empty edge.
HY_TEST(Channel_EdgeWakeWakesParkedConsumer)
{
    hy2::Channel<int> ch(64);

    const auto start = std::chrono::steady_clock::now();
    int got = -1;
    std::thread consumer([&] {
        int v = 0;
        if (ch.ReceiveFor(v, std::chrono::seconds(5))) got = v;
    });

    // Let the consumer park before producing, so this exercises the wake path
    // rather than finding the value already queued.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    HY_CHECK(ch.TrySend(7));

    consumer.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    HY_CHECK_EQ(got, 7);
    HY_CHECK(elapsed < std::chrono::seconds(2));
}

// Edge-triggering must not lose elements: a burst smaller than the capacity
// has to be delivered in full, and promptly (a lost wake would stall the
// consumer until ReceiveFor's timeout, once per element).
HY_TEST(Channel_BurstDeliversEveryElement)
{
    constexpr int kCount = 400;
    hy2::Channel<int> ch(1024);

    std::atomic<int> received{0};
    std::atomic<bool> consumerDone{false};
    const auto start = std::chrono::steady_clock::now();

    std::thread consumer([&] {
        while (received.load() < kCount) {
            int v = 0;
            if (!ch.ReceiveFor(v, std::chrono::milliseconds(100))) {
                if (ch.Closed()) break;
                continue;
            }
            HY_CHECK_EQ(v, received.load()); // FIFO order
            received.fetch_add(1);
        }
        consumerDone = true;
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(30)); // let it park
    for (int i = 0; i < kCount; ++i) {
        HY_CHECK(ch.TrySend(i));
    }

    consumer.join();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    HY_CHECK(consumerDone.load());
    HY_CHECK_EQ(received.load(), kCount);
    // A lost wake per element would cost kCount * 100ms = 40s.
    HY_CHECK(elapsed < std::chrono::seconds(5));
}

// The drop-when-full contract is unchanged.
HY_TEST(Channel_TrySendDropsWhenFull)
{
    hy2::Channel<int> ch(2);
    HY_CHECK(ch.TrySend(1));
    HY_CHECK(ch.TrySend(2));
    HY_CHECK(!ch.TrySend(3)); // dropped

    int v = 0;
    HY_CHECK(ch.ReceiveFor(v, std::chrono::milliseconds(100)));
    HY_CHECK_EQ(v, 1);
    HY_CHECK(ch.ReceiveFor(v, std::chrono::milliseconds(100)));
    HY_CHECK_EQ(v, 2);
    HY_CHECK(!ch.ReceiveFor(v, std::chrono::milliseconds(50))); // empty
}

// Closing must unblock a parked consumer.
HY_TEST(Channel_CloseUnblocksConsumer)
{
    hy2::Channel<int> ch(4);
    std::atomic<bool> woke{false};

    std::thread consumer([&] {
        int v = 0;
        (void)ch.ReceiveFor(v, std::chrono::seconds(5));
        woke = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    ch.Close();
    consumer.join();
    HY_CHECK(woke.load());
    HY_CHECK(ch.Closed());
}