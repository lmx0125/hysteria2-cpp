// quic_initial.hpp - QUIC Initial packet decryption for UDP sniffing.
// Decrypts QUIC Initial packets to extract TLS ClientHello SNI.
// Matches Go's extras/sniff/internal/quic/ implementation.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hy2::sniff {

// Parse and decrypt a QUIC Initial packet, extracting the TLS ClientHello.
// Returns the SNI hostname if successful, empty string otherwise.
// This is the C++ equivalent of Go's ReadCryptoPayload + ParseClientHelloSNI.
std::string ExtractQuicSNI(const uint8_t* data, size_t len);

// Check if a UDP packet looks like a QUIC Initial (long header, version 1 or 2).
bool IsQuicInitial(const uint8_t* data, size_t len);

} // namespace hy2::sniff
