// obfs_bench.cpp - Microbenchmarks for Salamander and Gecko obfuscation.
// Tests per-packet obfuscation/deobfuscation throughput without network I/O.
#include "bench.hpp"

#include "hy2/obfs/salamander.hpp"
#include "hy2/obfs/gecko.hpp"
#include "hy2/common.hpp"

#include <cstring>
#include <vector>

using namespace hy2;
using namespace hy2::obfs;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {
std::vector<uint8_t> MakePSK() {
    std::vector<uint8_t> psk(32);
    RandomBytes(psk.data(), psk.size());
    return psk;
}

std::vector<uint8_t> MakePayload(size_t len) {
    std::vector<uint8_t> buf(len);
    RandomBytes(buf.data(), len);
    return buf;
}
} // namespace

// ---------------------------------------------------------------------------
// Salamander obfuscate
// ---------------------------------------------------------------------------

HY_BENCH(salamander_obfuscate_64B, 64 + kSmSaltLen) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(64);
    std::vector<uint8_t> out(1200);
    for (int i = 0; i < 500; ++i) {
        obs.Obfuscate(payload.data(), payload.size(), out.data(), out.size());
    }
}

HY_BENCH(salamander_obfuscate_256B, 256 + kSmSaltLen) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(256);
    std::vector<uint8_t> out(1500);
    for (int i = 0; i < 500; ++i) {
        obs.Obfuscate(payload.data(), payload.size(), out.data(), out.size());
    }
}

HY_BENCH(salamander_obfuscate_512B, 512 + kSmSaltLen) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(512);
    std::vector<uint8_t> out(1500);
    for (int i = 0; i < 500; ++i) {
        obs.Obfuscate(payload.data(), payload.size(), out.data(), out.size());
    }
}

HY_BENCH(salamander_obfuscate_1200B, 1200 + kSmSaltLen) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(1200);
    std::vector<uint8_t> out(1500);
    for (int i = 0; i < 500; ++i) {
        obs.Obfuscate(payload.data(), payload.size(), out.data(), out.size());
    }
}

// ---------------------------------------------------------------------------
// Salamander deobfuscate
// ---------------------------------------------------------------------------

HY_BENCH(salamander_deobfuscate_64B, 0) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(64);
    std::vector<uint8_t> obfs(1200);
    int obfsLen = obs.Obfuscate(payload.data(), payload.size(), obfs.data(), obfs.size());
    std::vector<uint8_t> out(1200);
    for (int i = 0; i < 500; ++i) {
        obs.Deobfuscate(obfs.data(), static_cast<size_t>(obfsLen), out.data(), out.size());
    }
}

HY_BENCH(salamander_deobfuscate_1200B, 0) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(1200);
    std::vector<uint8_t> obfs(1500);
    int obfsLen = obs.Obfuscate(payload.data(), payload.size(), obfs.data(), obfs.size());
    std::vector<uint8_t> out(1500);
    for (int i = 0; i < 500; ++i) {
        obs.Deobfuscate(obfs.data(), static_cast<size_t>(obfsLen), out.data(), out.size());
    }
}

// ---------------------------------------------------------------------------
// Salamander roundtrip
// ---------------------------------------------------------------------------

HY_BENCH(salamander_roundtrip_64B, 64) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(64);
    std::vector<uint8_t> obfs(1200);
    std::vector<uint8_t> out(1200);
    for (int i = 0; i < 500; ++i) {
        int n = obs.Obfuscate(payload.data(), payload.size(), obfs.data(), obfs.size());
        obs.Deobfuscate(obfs.data(), static_cast<size_t>(n), out.data(), out.size());
    }
}

HY_BENCH(salamander_roundtrip_1200B, 1200) {
    auto psk = MakePSK();
    SalamanderObfuscator obs(psk);
    auto payload = MakePayload(1200);
    std::vector<uint8_t> obfs(1500);
    std::vector<uint8_t> out(1500);
    for (int i = 0; i < 500; ++i) {
        int n = obs.Obfuscate(payload.data(), payload.size(), obfs.data(), obfs.size());
        obs.Deobfuscate(obfs.data(), static_cast<size_t>(n), out.data(), out.size());
    }
}

// ---------------------------------------------------------------------------
// Gecko frame encode/decode
// ---------------------------------------------------------------------------

HY_BENCH(gecko_encode_frame_short, 400) {
    auto payload = MakePayload(400);
    FrameHeader h;
    h.msgID = 42;
    h.chunkIdx = 0;
    h.totalChunks = 2;
    h.padLen = 50;
    std::vector<uint8_t> out(kGeckoHeaderSize + h.padLen + payload.size());
    for (int i = 0; i < 500; ++i) {
        EncodeFrame(h, payload.data(), payload.size(), out.data(), out.size());
    }
}

HY_BENCH(gecko_encode_frame_large, 1200) {
    auto payload = MakePayload(1200);
    FrameHeader h;
    h.msgID = 42;
    h.chunkIdx = 0;
    h.totalChunks = 4;
    h.padLen = 100;
    std::vector<uint8_t> out(kGeckoHeaderSize + h.padLen + payload.size());
    for (int i = 0; i < 500; ++i) {
        EncodeFrame(h, payload.data(), payload.size(), out.data(), out.size());
    }
}

HY_BENCH(gecko_decode_frame_short, 0) {
    auto payload = MakePayload(400);
    FrameHeader h;
    h.msgID = 42;
    h.chunkIdx = 0;
    h.totalChunks = 2;
    h.padLen = 50;
    std::vector<uint8_t> buf(kGeckoHeaderSize + h.padLen + payload.size());
    EncodeFrame(h, payload.data(), payload.size(), buf.data(), buf.size());
    for (int i = 0; i < 500; ++i) {
        (void)DecodeFrame(buf.data(), buf.size());
    }
}

HY_BENCH(gecko_decode_frame_large, 0) {
    auto payload = MakePayload(1200);
    FrameHeader h;
    h.msgID = 42;
    h.chunkIdx = 0;
    h.totalChunks = 4;
    h.padLen = 100;
    std::vector<uint8_t> buf(kGeckoHeaderSize + h.padLen + payload.size());
    EncodeFrame(h, payload.data(), payload.size(), buf.data(), buf.size());
    for (int i = 0; i < 500; ++i) {
        (void)DecodeFrame(buf.data(), buf.size());
    }
}

// Gecko roundtrip
HY_BENCH(gecko_roundtrip_frame, 400) {
    auto payload = MakePayload(400);
    FrameHeader h;
    h.msgID = 42;
    h.chunkIdx = 1;
    h.totalChunks = 3;
    h.padLen = 30;
    std::vector<uint8_t> buf(kGeckoHeaderSize + h.padLen + payload.size());
    for (int i = 0; i < 500; ++i) {
        EncodeFrame(h, payload.data(), payload.size(), buf.data(), buf.size());
        (void)DecodeFrame(buf.data(), buf.size());
    }
}
