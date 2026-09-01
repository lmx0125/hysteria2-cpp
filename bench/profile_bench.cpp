// profile_bench.cpp - Targeted micro-benchmarks to isolate specific costs.
// Answers: what exactly is slow in padding, UDP parse, and defrag?
#include "bench.hpp"

#include "hy2/common.hpp"
#include "hy2/protocol.hpp"
#include "hy2/frag.hpp"
#include "hy2/varint.hpp"

#include <cstring>
#include <vector>

using namespace hy2;
using namespace hy2::proto;
using namespace hy2::frag;

// ============================================================================
// Padding isolation: what part is expensive?
// ============================================================================

// Just the RNG calls (no string allocation)
HY_BENCH(padding_rng_only_2048, 0) {
    for (int i = 0; i < 100; ++i) {
        volatile uint64_t x = 0;
        for (int j = 0; j < 2048; j++) {
            x = RandomUint64();
        }
        (void)x;
    }
}

// Just the modulo operations (no RNG, no allocation)
HY_BENCH(padding_modulo_only_2048, 0) {
    uint64_t buf[2048];
    for (int i = 0; i < 2048; i++) buf[i] = RandomUint64();
    for (int i = 0; i < 100; ++i) {
        volatile char c = 0;
        for (int j = 0; j < 2048; j++) {
            c = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[buf[j] % 62];
        }
        (void)c;
    }
}

// String allocation only (no RNG)
HY_BENCH(padding_alloc_only_2048, 2048) {
    for (int i = 0; i < 100; ++i) {
        std::string s(2048, 'x');
        (void)s;
    }
}

// Full Padding::String
HY_BENCH(padding_full_string_2048, 2048) {
    Padding p{256, 2048};
    for (int i = 0; i < 100; ++i) {
        (void)p.String();
    }
}

// ============================================================================
// UDP parse isolation: what part is expensive?
// ============================================================================

namespace {
UDPMessage MakeMsg(size_t dataSize) {
    UDPMessage m;
    m.SessionID = 0x12345678;
    m.PacketID = 1;
    m.FragID = 0;
    m.FragCount = 1;
    m.Addr = "127.0.0.1:53";
    m.Data.resize(dataSize);
    RandomBytes(m.Data.data(), dataSize);
    return m;
}

std::vector<uint8_t> Serialize(const UDPMessage& m) {
    std::vector<uint8_t> buf(1500);
    int n = m.Serialize(buf.data(), buf.size());
    buf.resize(static_cast<size_t>(n));
    return buf;
}
} // namespace

// Just header parsing (8 bytes + varint)
HY_BENCH(udp_parse_header_only, 0) {
    auto raw = Serialize(MakeMsg(1200));
    for (int i = 0; i < 500; ++i) {
        // Parse just the 8-byte header + varint
        const uint8_t* msg = raw.data();
        uint32_t sid = (uint32_t(msg[0]) << 24) | (uint32_t(msg[1]) << 16) |
                        (uint32_t(msg[2]) << 8) | uint32_t(msg[3]);
        uint16_t pid = uint16_t((uint16_t(msg[4]) << 8) | msg[5]);
        (void)sid; (void)pid;
    }
}

// Address string construction only
HY_BENCH(udp_parse_addr_string, 0) {
    auto raw = Serialize(MakeMsg(1200));
    const uint8_t* msg = raw.data();
    size_t consumed = 0;
    auto addrLenOpt = VarintParse(msg + 8, raw.size() - 8, &consumed);
    size_t addrLen = *addrLenOpt;
    for (int i = 0; i < 500; ++i) {
        std::string addr(reinterpret_cast<const char*>(msg + 8 + consumed), addrLen);
        (void)addr;
    }
}

// Data vector construction only
HY_BENCH(udp_parse_data_vector, 0) {
    auto raw = Serialize(MakeMsg(1200));
    const uint8_t* msg = raw.data();
    size_t consumed = 0;
    auto addrLenOpt = VarintParse(msg + 8, raw.size() - 8, &consumed);
    size_t headerLen = 8 + consumed + *addrLenOpt;
    size_t dataLen = raw.size() - headerLen;
    for (int i = 0; i < 500; ++i) {
        std::vector<uint8_t> data(msg + headerLen, msg + headerLen + dataLen);
        (void)data;
    }
}

// Full parse
HY_BENCH(udp_parse_full_1200B, 0) {
    auto raw = Serialize(MakeMsg(1200));
    for (int i = 0; i < 500; ++i) {
        (void)ParseUDPMessage(raw);
    }
}

// In-place parse (reuses buffer across iterations)
HY_BENCH(udp_parse_inplace_1200B, 0) {
    auto raw = Serialize(MakeMsg(1200));
    UDPMessage m;
    for (int i = 0; i < 500; ++i) {
        ParseUDPMessageInPlace(m, raw.data(), raw.size());
    }
}

// ============================================================================
// Defrag isolation: what part is expensive?
// ============================================================================

namespace {
UDPMessage MakeFrag(size_t dataSize, uint16_t pktID = 1) {
    UDPMessage m;
    m.SessionID = 0xDEADBEEF;
    m.PacketID = pktID;
    m.FragID = 0;
    m.FragCount = 2;
    m.Addr = "10.0.0.1:53";
    m.Data.resize(dataSize);
    RandomBytes(m.Data.data(), dataSize);
    return m;
}
} // namespace

// Defragger construction only
HY_BENCH(defrag_construction_only, 0) {
    for (int i = 0; i < 500; ++i) {
        Defragger d;
        (void)d;
    }
}

// shared_ptr allocation only
HY_BENCH(defrag_shared_ptr_alloc, 0) {
    auto m = MakeFrag(500);
    for (int i = 0; i < 500; ++i) {
        auto p = std::make_shared<const UDPMessage>(m);
        (void)p;
    }
}

// Single fragment Feed (no assembly)
HY_BENCH(defrag_single_feed, 500) {
    auto m = MakeFrag(500);
    for (int i = 0; i < 500; ++i) {
        Defragger d;
        (void)d.Feed(m);
    }
}

// Two fragments Feed (triggers assembly)
HY_BENCH(defrag_two_feed_assembly, 1000) {
    auto m1 = MakeFrag(500);
    m1.FragID = 0;
    auto m2 = m1;
    m2.FragID = 1;
    for (int i = 0; i < 500; ++i) {
        Defragger d;
        (void)d.Feed(m1);
        (void)d.Feed(m2);
    }
}
