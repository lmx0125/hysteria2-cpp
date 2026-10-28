#include "hytest.hpp"
#include "hy2/detail/receive_buffer.hpp"

#include <deque>
#include <random>
#include <vector>

using hy2::detail::ReceiveBuffer;

HY_TEST(ReceiveBuffer_EmptyAndReuse) {
    ReceiveBuffer b;
    HY_CHECK_EQ(b.Read(nullptr, 0), size_t{0});
    b.Append(nullptr, 0);
    HY_CHECK_EQ(b.capacity(), size_t{0});
    const uint8_t data[] = {1, 2, 3};
    uint8_t out[8]{};
    b.Append(data, sizeof(data));
    const size_t capacity = b.capacity();
    HY_CHECK_EQ(b.Read(out, sizeof(out)), sizeof(data));
    HY_CHECK_EQ(out[2], uint8_t{3});
    b.Append(data, sizeof(data));
    b.clear();
    HY_CHECK_EQ(b.size(), size_t{0});
    HY_CHECK_EQ(b.capacity(), capacity);
    b.Append(data, sizeof(data));
    HY_CHECK_EQ(b.Read(out, 2), size_t{2});
    HY_CHECK_EQ(out[0], uint8_t{1});
}

HY_TEST(ReceiveBuffer_WrapAndGrowPreserveOrder) {
    ReceiveBuffer b;
    std::deque<uint8_t> expected;
    uint64_t sequence = 0;
    auto append = [&](size_t n) {
        std::vector<uint8_t> data(n);
        for (auto& v : data) {
            v = static_cast<uint8_t>((sequence * 17 + sequence / 251) & 255);
            ++sequence;
            expected.push_back(v);
        }
        b.Append(data.data(), data.size());
    };
    auto read = [&](size_t n) {
        std::vector<uint8_t> out(n);
        const size_t want = std::min(n, expected.size());
        HY_CHECK_EQ(b.Read(out.data(), n), want);
        for (size_t i = 0; i < want; ++i) {
            HY_CHECK_EQ(out[i], expected.front());
            expected.pop_front();
        }
        HY_CHECK_EQ(b.size(), expected.size());
    };
    append(4096);  // full ring
    read(3000);
    append(2500);  // wrap
    append(5000);  // grow while wrapped
    read(8192);
    read(10000);

    std::mt19937 rng(20261009);
    for (int i = 0; i < 2000; ++i) {
        if (expected.size() > 32768 || (rng() & 1)) read(rng() % 8193);
        else append(rng() % 8193);
    }
    read(expected.size());
    HY_CHECK_EQ(b.size(), size_t{0});
}

HY_TEST(ReceiveBuffer_SustainedBacklogHasBoundedCapacity) {
    ReceiveBuffer b;
    constexpr size_t backlog = 1024 * 1024;
    constexpr size_t chunk = 32 * 1024;
    std::vector<uint8_t> data(backlog, 0x5a), out(chunk);
    b.Append(data.data(), data.size());
    const size_t capacity = b.capacity();
    // 128 MiB consumed without ever emptying the queue. The old vector kept
    // every consumed prefix and grew with total traffic despite flow control.
    for (int i = 0; i < 4096; ++i) {
        HY_CHECK_EQ(b.Read(out.data(), chunk), chunk);
        HY_CHECK_EQ(out.front(), uint8_t{0x5a});
        HY_CHECK_EQ(out.back(), uint8_t{0x5a});
        b.Append(data.data(), chunk);
        HY_CHECK_EQ(b.size(), backlog);
        HY_CHECK_EQ(b.capacity(), capacity);
    }
}

HY_TEST(ReceiveBuffer_OverflowLeavesContentsIntact) {
    ReceiveBuffer b;
    const uint8_t value = 7;
    b.Append(&value, 1);
    bool threw = false;
    try { b.Append(&value, std::numeric_limits<size_t>::max()); }
    catch (const std::length_error&) { threw = true; }
    HY_CHECK(threw);
    uint8_t out = 0;
    HY_CHECK_EQ(b.Read(&out, 1), size_t{1});
    HY_CHECK_EQ(out, value);
}
