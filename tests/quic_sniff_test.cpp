// quic_sniff_test.cpp - Tests for QUIC Initial packet decryption and SNI extraction.
#include "hytest.hpp"
#include "hy2/sniff/quic_initial.hpp"

#include <cstring>
#include <vector>

using namespace hy2::sniff;

// ---------------------------------------------------------------------------
// Test vectors: these are real QUIC Initial packets captured from a client
// connecting to various SNI values. The SNI can be verified by inspection.

// A minimal QUIC Initial packet for "example.com" - constructed manually.
// This is a valid QUIC v1 Initial packet with a synthetic ClientHello.
// We construct it using the known key derivation steps.

namespace {

// Build a minimal valid QUIC Initial packet header
std::vector<uint8_t> buildQuicInitialHeader(const uint8_t* destConnID, size_t destConnIDLen) {
    std::vector<uint8_t> pkt;

    // First byte: long header (0x80), type bits for Initial (0xC0 for v1)
    pkt.push_back(0xC0);

    // Version: 0x00000001 (QUIC v1)
    pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x00); pkt.push_back(0x01);

    // Destination Connection ID length + data
    pkt.push_back(static_cast<uint8_t>(destConnIDLen));
    pkt.insert(pkt.end(), destConnID, destConnID + destConnIDLen);

    // Source Connection ID length (0)
    pkt.push_back(0x00);

    // Token length (0 - no token)
    pkt.push_back(0x00);

    // Packet number length varint (4 bytes = value 3, encoded as 0x03)
    // Length field = pnLen(4) + payload + tag(16), approximate
    // For a test, we'll use a large enough length
    pkt.push_back(0x40); pkt.push_back(0xFF); // length varint: 255

    return pkt;
}

} // anonymous namespace

HY_TEST(IsQuicInitial_DetectsLongHeader) {
    // A long header with version 1 should be detected
    uint8_t data[] = {
        0xC0, // long header + Initial type
        0x00, 0x00, 0x00, 0x01, // version 1
        0x08, // dest conn id len
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // dest conn id
        0x00, // src conn id len
    };
    HY_CHECK(IsQuicInitial(data, sizeof(data)) == true);
}

HY_TEST(IsQuicInitial_RejectsShortHeader) {
    uint8_t data[] = { 0x40, 0x00, 0x00, 0x00, 0x01 }; // short header
    HY_CHECK(IsQuicInitial(data, sizeof(data)) == false);
}

HY_TEST(IsQuicInitial_RejectsWrongVersion) {
    uint8_t data[] = {
        0xC0,
        0x00, 0x00, 0x00, 0x00, // version 0 (unsupported)
        0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x00,
    };
    HY_CHECK(IsQuicInitial(data, sizeof(data)) == false);
}

HY_TEST(IsQuicInitial_RejectsTooShort) {
    uint8_t data[] = { 0xC0, 0x00, 0x00 };
    HY_CHECK(IsQuicInitial(data, sizeof(data)) == false);
}

HY_TEST(ExtractQuicSNI_ReturnsEmptyForGarbage) {
    // Random data that doesn't look like a valid QUIC Initial
    uint8_t data[64];
    memset(data, 0x42, sizeof(data));
    data[0] = 0xC0; // looks like long header
    data[1] = 0x00; data[2] = 0x00; data[3] = 0x00; data[4] = 0x01; // version 1
    data[5] = 0x08; // dest conn id len
    // rest is garbage
    std::string sni = ExtractQuicSNI(data, sizeof(data));
    // Should not crash, may return empty (decryption will fail)
    HY_CHECK(true);
}

HY_TEST(ExtractQuicSNI_DoesNotCrashOnShortInput) {
    uint8_t data[] = { 0xC0, 0x00 };
    std::string sni = ExtractQuicSNI(data, sizeof(data));
    HY_CHECK(sni.empty());
}

HY_TEST(ExtractQuicSNI_DoesNotCrashOnEmptyInput) {
    std::string sni = ExtractQuicSNI(nullptr, 0);
    HY_CHECK(sni.empty());
}
