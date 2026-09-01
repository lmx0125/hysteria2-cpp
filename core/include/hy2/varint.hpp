// varint.hpp - QUIC variable-length integers (RFC 9000 §16).
// Mirrors quic-go/quicvarint used by the original Go implementation.
#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

#include "common.hpp"
#include "error.hpp"
#include "io.hpp"

namespace hy2 {

// Maximum values for each varint length (mirrors Go constants).
constexpr uint64_t kMaxVarInt1 = 63;
constexpr uint64_t kMaxVarInt2 = 16383;
constexpr uint64_t kMaxVarInt4 = 1073741823;
constexpr uint64_t kMaxVarInt8 = 4611686018427387903ULL;

// VarintLen returns the number of bytes required to encode v.
inline size_t VarintLen(uint64_t v) {
    if (v <= kMaxVarInt1) return 1;
    if (v <= kMaxVarInt2) return 2;
    if (v <= kMaxVarInt4) return 4;
    if (v <= kMaxVarInt8) return 8;
    return 0; // doesn't fit into 62 bits
}

// VarintPut writes v into buf (which must be >= VarintLen(v) bytes).
// Returns the number of bytes written. Panics (via assert/throw) on overflow,
// mirroring the Go panic in varintPut.
inline size_t VarintPut(uint8_t* b, uint64_t i) {
    if (i <= kMaxVarInt1) {
        b[0] = static_cast<uint8_t>(i);
        return 1;
    }
    if (i <= kMaxVarInt2) {
        b[0] = static_cast<uint8_t>(i >> 8) | 0x40;
        b[1] = static_cast<uint8_t>(i);
        return 2;
    }
    if (i <= kMaxVarInt4) {
        b[0] = static_cast<uint8_t>(i >> 24) | 0x80;
        b[1] = static_cast<uint8_t>(i >> 16);
        b[2] = static_cast<uint8_t>(i >> 8);
        b[3] = static_cast<uint8_t>(i);
        return 4;
    }
    if (i <= kMaxVarInt8) {
        b[0] = static_cast<uint8_t>(i >> 56) | 0xc0;
        b[1] = static_cast<uint8_t>(i >> 48);
        b[2] = static_cast<uint8_t>(i >> 40);
        b[3] = static_cast<uint8_t>(i >> 32);
        b[4] = static_cast<uint8_t>(i >> 24);
        b[5] = static_cast<uint8_t>(i >> 16);
        b[6] = static_cast<uint8_t>(i >> 8);
        b[7] = static_cast<uint8_t>(i);
        return 8;
    }
    throw Error("value doesn't fit into 62 bits");
}

// VarintAppend appends the encoded value to out. Mirrors quicvarint.Append.
inline void VarintAppend(std::vector<uint8_t>& out, uint64_t v) {
    size_t n = VarintLen(v);
    size_t base = out.size();
    out.resize(base + n);
    VarintPut(out.data() + base, v);
}

// VarintParse parses a varint from buf.
// Returns the value and sets consumed; returns std::nullopt when the buffer
// is truncated. Mirrors quicvarint.Parse.
inline std::optional<uint64_t> VarintParse(const uint8_t* buf, size_t len, size_t* consumed = nullptr) {
    if (len == 0) return std::nullopt;
    uint8_t first = buf[0];
    if (first <= kMaxVarInt1) {
        if (consumed) *consumed = 1;
        return first;
    } else if ((first & 0xc0) == 0x40) {
        if (len < 2) return std::nullopt;
        if (consumed) *consumed = 2;
        return (static_cast<uint64_t>(first & 0x3f) << 8) | buf[1];
    } else if ((first & 0xc0) == 0x80) {
        if (len < 4) return std::nullopt;
        if (consumed) *consumed = 4;
        return (static_cast<uint64_t>(first & 0x3f) << 24) |
               (static_cast<uint64_t>(buf[1]) << 16) |
               (static_cast<uint64_t>(buf[2]) << 8) |
               static_cast<uint64_t>(buf[3]);
    } else {
        if (len < 8) return std::nullopt;
        if (consumed) *consumed = 8;
        return (static_cast<uint64_t>(first & 0x3f) << 56) |
               (static_cast<uint64_t>(buf[1]) << 48) |
               (static_cast<uint64_t>(buf[2]) << 40) |
               (static_cast<uint64_t>(buf[3]) << 32) |
               (static_cast<uint64_t>(buf[4]) << 24) |
               (static_cast<uint64_t>(buf[5]) << 16) |
               (static_cast<uint64_t>(buf[6]) << 8) |
               static_cast<uint64_t>(buf[7]);
    }
}

// VarintRead reads a varint from a stream. Throws on EOF / error.
// Mirrors quicvarint.Read.
inline uint64_t VarintRead(IByteReader& r) {
    uint8_t first = 0;
    ReadFull(r, &first, 1);
    // determine length from the two high bits
    size_t n;
    if (first <= kMaxVarInt1) {
        n = 1;
    } else if ((first & 0xc0) == 0x40) {
        n = 2;
    } else if ((first & 0xc0) == 0x80) {
        n = 4;
    } else {
        n = 8;
    }
    uint8_t rest[8];
    rest[0] = first;
    if (n > 1) ReadFull(r, rest + 1, n - 1);
    auto v = VarintParse(rest, n);
    return *v;
}

} // namespace hy2
