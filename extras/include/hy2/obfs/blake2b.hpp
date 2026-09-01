// blake2b.hpp - Self-contained pure-C++ BLAKE2b (RFC 7693).
// Replaces golang.org/x/crypto/blake2b for the extras package.
#pragma once

#include <cstddef>
#include <cstdint>

namespace hy2::crypto {

// 256-bit digest (BLAKE2b-256), like Go's blake2b.Sum256.
struct Digest256 {
    uint8_t b[32];
};

// One-shot unkeyed BLAKE2b-256 over data[0..len).
Digest256 Blake2bSum256(const uint8_t* data, size_t len);

} // namespace hy2::crypto
