// frag_bench.cpp - Microbenchmarks for UDP message fragmentation and
// defragmentation. Tests the frag/defrag pipeline which sits on the
// hot path for every UDP packet.
#include "bench.hpp"

#include "hy2/frag.hpp"
#include "hy2/protocol.hpp"
#include "hy2/common.hpp"

#include <vector>

using namespace hy2;
using namespace hy2::frag;
using namespace hy2::proto;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {
UDPMessage MakeFragMessage(size_t dataSize, uint16_t pktID = 1) {
    UDPMessage m;
    m.SessionID = 0xDEADBEEF;
    m.PacketID = pktID;
    m.FragID = 0;
    m.FragCount = 1;
    m.Addr = "10.0.0.1:53";
    m.Data.resize(dataSize);
    RandomBytes(m.Data.data(), dataSize);
    return m;
}
} // namespace

// ---------------------------------------------------------------------------
// Fragmentation
// ---------------------------------------------------------------------------

HY_BENCH(frag_no_frag_needed, 1200) {
    auto m = MakeFragMessage(100);
    for (int i = 0; i < 500; ++i) {
        (void)FragUDPMessage(m, 1200);
    }
}

HY_BENCH(frag_two_frags, 600) {
    auto m = MakeFragMessage(1100);
    for (int i = 0; i < 500; ++i) {
        (void)FragUDPMessage(m, 1200);
    }
}

HY_BENCH(frag_four_frags, 300) {
    auto m = MakeFragMessage(2200);
    for (int i = 0; i < 500; ++i) {
        (void)FragUDPMessage(m, 1200);
    }
}

// ---------------------------------------------------------------------------
// Defragmentation
// ---------------------------------------------------------------------------

HY_BENCH(defrag_single_fragment, 0) {
    auto m = MakeFragMessage(100);
    for (int i = 0; i < 500; ++i) {
        Defragger d;
        (void)d.Feed(m);
    }
}

HY_BENCH(defrag_two_fragments, 1100) {
    auto m = MakeFragMessage(1100);
    auto frags = FragUDPMessage(m, 1200);
    for (int i = 0; i < 500; ++i) {
        Defragger d;
        for (auto& f : frags) {
            (void)d.Feed(f);
        }
    }
}

HY_BENCH(defrag_four_fragments, 2200) {
    auto m = MakeFragMessage(2200);
    auto frags = FragUDPMessage(m, 1200);
    for (int i = 0; i < 100; ++i) {
        Defragger d;
        for (auto& f : frags) {
            (void)d.Feed(f);
        }
    }
}

// Measure pure reassembly cost (exclude Defragger construction)
HY_BENCH(defrag_assemble_only, 2200) {
    auto m = MakeFragMessage(2200);
    auto frags = FragUDPMessage(m, 1200);
    for (int i = 0; i < 500; ++i) {
        Defragger d;
        for (size_t j = 0; j + 1 < frags.size(); ++j) {
            (void)d.Feed(frags[j]);
        }
        (void)d.Feed(frags.back());
    }
}

// ---------------------------------------------------------------------------
// Fragmentation + defragmentation roundtrip
// ---------------------------------------------------------------------------

HY_BENCH(frag_defrag_roundtrip_1100B, 1100) {
    for (int i = 0; i < 100; ++i) {
        auto m = MakeFragMessage(1100);
        auto frags = FragUDPMessage(m, 1200);
        Defragger d;
        std::shared_ptr<const UDPMessage> result;
        for (auto& f : frags) {
            result = d.Feed(f);
        }
        (void)result;
    }
}

HY_BENCH(frag_defrag_roundtrip_2200B, 2200) {
    for (int i = 0; i < 100; ++i) {
        auto m = MakeFragMessage(2200);
        auto frags = FragUDPMessage(m, 1200);
        Defragger d;
        std::shared_ptr<const UDPMessage> result;
        for (auto& f : frags) {
            result = d.Feed(f);
        }
        (void)result;
    }
}

// ---------------------------------------------------------------------------
// Stress: multiple concurrent defraggers (simulating multiple sessions)
// ---------------------------------------------------------------------------

HY_BENCH(defrag_multi_session_100, 500) {
    // 100 sessions, each processing 10 packets
    std::vector<Defragger> defraggers(100);
    for (int i = 0; i < 100; ++i) {
        auto m = MakeFragMessage(500, static_cast<uint16_t>(i));
        defraggers[i % 100].Feed(m);
    }
}

// ---------------------------------------------------------------------------
// Large message fragmentation (multi-fragment)
// ---------------------------------------------------------------------------

HY_BENCH(frag_large_4400B, 1100) {
    auto m = MakeFragMessage(4400);
    for (int i = 0; i < 100; ++i) {
        (void)FragUDPMessage(m, 1200);
    }
}

HY_BENCH(defrag_large_4400B, 4400) {
    auto m = MakeFragMessage(4400);
    auto frags = FragUDPMessage(m, 1200);
    for (int i = 0; i < 100; ++i) {
        Defragger d;
        for (auto& f : frags) {
            (void)d.Feed(f);
        }
    }
}
