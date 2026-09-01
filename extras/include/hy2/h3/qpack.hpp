// qpack.hpp - Minimal QPACK (RFC 9204) encoder/decoder for Hysteria2 auth.
//
// Strategy for maximum interop with quic-go (official Hysteria2):
//  - Both sides advertise QPACK_MAX_TABLE_CAPACITY=0 and
//    QPACK_BLOCKED_STREAMS=0, forcing static-table/literal-only encodings.
//  - Decoder supports: indexed field line (static), literal field line with
//    name reference (static), literal field line with literal name, and
//    Huffman-coded strings (table reused from the linked nghttp3 build).
//  - Encoder emits literal lines (raw strings), optionally referencing
//    well-known static names.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace hy2::h3 {

using Header = std::pair<std::string, std::string>;

// Decode a complete HEADERS field section. Throws std::runtime_error on
// malformed input or dynamic-table references (which we never negotiate).
std::vector<Header> QpackDecode(const uint8_t* data, size_t len);
inline std::vector<Header> QpackDecode(const std::vector<uint8_t>& v) {
    return QpackDecode(v.data(), v.size());
}

// Encode headers using only literal representations (raw strings).
std::vector<uint8_t> QpackEncode(const std::vector<Header>& headers);

// ---------------------------------------------------------------------------
// QPACK static table (RFC 9204 Appendix A) - subset needed for lookups.
// Returns index or -1 when not present with an EMPTY value slot requirement.
// ---------------------------------------------------------------------------
int QpackStaticIndex(const std::string& name, const std::string& value);

// Name of static entry at index, or empty string when out of range.
std::string QpackStaticName(int index);

// Decode a Huffman-encoded QPACK string. Throws on invalid encoding.
std::string HuffmanDecode(const uint8_t* src, size_t len);

// Debug: hex of huffman encoding.
std::string QpackDebugHuffmanHex(const std::string& s);
std::string QpackDebugHuffmanTrace(const uint8_t* src, size_t len);

} // namespace hy2::h3


