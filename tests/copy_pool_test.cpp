// copy_pool_test.cpp - regression tests for the copy-buffer pool in copy.cpp.
//
// The pool used to leak: CopyTwoWay runs one thread per direction, each thread
// takes a 32KB block and hands it back with TLSPut on exit. TLSPut only drains
// to the shared central pool once a single thread has accumulated 64 blocks,
// which a relay thread never does, so the block stayed on the thread-local
// freelist and the pointer was dropped when the thread exited (TLSData had no
// destructor). Net effect: 2 x 32KB leaked per proxied TCP connection.
#include "hytest.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "hy2/copy.hpp"
#include "hy2/io.hpp"

namespace {

using hy2::IByteReaderWriter;

// Read returns 0 immediately (clean EOF); Write accumulates.
struct EofSink : public IByteReaderWriter {
    std::vector<uint8_t> got;
    size_t Read(uint8_t*, size_t) override { return 0; }
    void Write(const uint8_t* p, size_t n) override { got.insert(got.end(), p, p + n); }
};

// Read serves the buffer once and then EOFs; Write accumulates.
struct DataSource : public IByteReaderWriter {
    std::vector<uint8_t> src;
    size_t pos = 0;
    std::vector<uint8_t> got;

    explicit DataSource(std::vector<uint8_t> d) : src(std::move(d)) {}

    size_t Read(uint8_t* p, size_t n) override {
        if (pos >= src.size()) return 0;
        const size_t k = std::min(n, src.size() - pos);
        std::memcpy(p, src.data() + pos, k);
        pos += k;
        return k;
    }
    void Write(const uint8_t* p, size_t n) override { got.insert(got.end(), p, p + n); }
};

// Minimal ITrafficLogger: counts what the relay reports and always allows.
struct RecordingLogger : public hy2::server::ITrafficLogger {
    uint64_t tx = 0;
    uint64_t rx = 0;
    int calls = 0;

    bool LogTraffic(const std::string&, uint64_t txBytes, uint64_t rxBytes) override {
        tx += txBytes;
        rx += rxBytes;
        ++calls;
        return true;
    }
    void LogOnlineState(const std::string&, bool) override {}
};

} // namespace

// Sanity: the relay still moves bytes in both directions and reports clean EOF.
HY_TEST(CopyTwoWay_TransfersDataThenEof)
{
    auto a = std::make_shared<DataSource>(std::vector<uint8_t>{1, 2, 3, 4, 5});
    auto b = std::make_shared<EofSink>();

    // t1: b -> a, t2: a -> b. b EOFs at once; a has five bytes to hand over.
    const std::string err = hy2::server::CopyTwoWay(a, b);
    HY_CHECK_EQ(err, std::string());
    HY_CHECK_EQ(b->got.size(), static_cast<size_t>(5));
    HY_CHECK_EQ(b->got[0], static_cast<uint8_t>(1));
    HY_CHECK_EQ(b->got[4], static_cast<uint8_t>(5));
}

// A larger payload must arrive intact across the 32KB copy buffer boundary.
HY_TEST(CopyTwoWay_LargePayloadIntact)
{
    std::vector<uint8_t> payload(100 * 1024);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>(i * 31 + 7);
    }
    auto a = std::make_shared<DataSource>(payload);
    auto b = std::make_shared<EofSink>();

    const std::string err = hy2::server::CopyTwoWay(a, b);
    HY_CHECK_EQ(err, std::string());
    HY_CHECK_EQ(b->got.size(), payload.size());
    HY_CHECK(b->got == payload);
}

// The regression test for the leak: every relay direction thread must hand its
// block back to the central pool when it exits, and repeated relays must not
// keep taking fresh 32KB blocks from the heap.
HY_TEST(CopyPool_BlocksReturnedWhenRelayThreadsExit)
{
    using namespace hy2::server;

    constexpr int kRelays = 24; // 2 direction threads each => 48 blocks
    const CopyPoolStats before = CopyPoolStatsSnapshot();

    for (int i = 0; i < kRelays; ++i) {
        auto a = std::make_shared<EofSink>();
        auto b = std::make_shared<EofSink>();
        CopyTwoWay(a, b);
    }

    const CopyPoolStats after = CopyPoolStatsSnapshot();
    const uint64_t returned = after.blocksReturnedToCentral - before.blocksReturnedToCentral;
    const uint64_t fresh = after.blocksFreshAllocs - before.blocksFreshAllocs;

    // Before the fix this was 0: TLSPut parked the block on the dying thread's
    // freelist and the pointer was dropped, so nothing ever reached central.
    HY_CHECK(returned >= static_cast<uint64_t>(2 * kRelays));

    // Before the fix this was exactly 2*kRelays (one fresh 32KB per thread,
    // leaked). A working pool refills once and then recycles.
    HY_CHECK(fresh < static_cast<uint64_t>(2 * kRelays));
}

// Same guarantee for the traffic-logging variant used by the main server path.
HY_TEST(CopyPool_ExVariantRecyclesBlocks)
{
    using namespace hy2::server;

    constexpr int kRelays = 12;
    constexpr size_t kPayload = 4096;
    const CopyPoolStats before = CopyPoolStatsSnapshot();

    RecordingLogger logger;
    for (int i = 0; i < kRelays; ++i) {
        std::vector<uint8_t> payload(kPayload, static_cast<uint8_t>(i));
        auto a = std::make_shared<DataSource>(payload);
        auto b = std::make_shared<EofSink>();
        StreamStats stats;
        const std::string err = CopyTwoWayEx("user", a, b, &logger, stats);
        HY_CHECK_EQ(err, std::string());
        // t2 relays a -> b, so the payload is reported as Tx on this side.
        HY_CHECK_EQ(stats.Tx.load(), static_cast<uint64_t>(kPayload));
        HY_CHECK_EQ(b->got.size(), kPayload);
    }

    HY_CHECK_EQ(logger.tx, static_cast<uint64_t>(kRelays) * kPayload);
    HY_CHECK(logger.calls > 0);

    const CopyPoolStats after = CopyPoolStatsSnapshot();
    const uint64_t returned = after.blocksReturnedToCentral - before.blocksReturnedToCentral;
    const uint64_t fresh = after.blocksFreshAllocs - before.blocksFreshAllocs;

    HY_CHECK(returned >= static_cast<uint64_t>(2 * kRelays));
    HY_CHECK(fresh < static_cast<uint64_t>(2 * kRelays));
}