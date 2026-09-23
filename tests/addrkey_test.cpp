// addrkey_test.cpp - Tests for the listener's peer-address hash.
//
// AddrKey maps an inbound datagram's source address to a connection slot. A
// collision would route one client's packets into another client's connection,
// so the properties that matter are: stability (same peer -> same key) and
// injectivity over the address space that actually occurs (distinct peers ->
// distinct keys). The key used to be computed over the whole zero-filled
// 132-byte sockaddr_storage scratch buffer; it now covers only the meaningful
// bytes, so these tests pin down that no address bits were dropped.
#include "hytest.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/quic_backend/ngtcp2_listener.hpp"

#include <cstdint>
#include <cstring>
#include <set>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
#endif

using hy2::quic_backend::AddrKeyForTest;

namespace {

uint64_t KeyV4(const char* ip, uint16_t port) {
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    return AddrKeyForTest(reinterpret_cast<const struct sockaddr*>(&sa), sizeof(sa));
}

uint64_t KeyV6(const uint8_t addr[16], uint16_t port) {
    struct sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    std::memcpy(&sa.sin6_addr, addr, 16);
    return AddrKeyForTest(reinterpret_cast<const struct sockaddr*>(&sa), sizeof(sa));
}

} // namespace

// Same peer must always hash to the same slot.
HY_TEST(AddrKey_StableForSamePeer)
{
    HY_CHECK_EQ(KeyV4("192.0.2.7", 443), KeyV4("192.0.2.7", 443));
    const uint8_t a[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    HY_CHECK_EQ(KeyV6(a, 443), KeyV6(a, 443));
}

// Distinct peers must land in distinct slots.
HY_TEST(AddrKey_DistinctIPv4Addresses)
{
    HY_CHECK(KeyV4("192.0.2.7", 443) != KeyV4("192.0.2.8", 443));
    HY_CHECK(KeyV4("192.0.2.7", 443) != KeyV4("192.0.3.7", 443));
    HY_CHECK(KeyV4("10.0.0.1", 443) != KeyV4("10.0.0.1", 444));
    HY_CHECK(KeyV4("10.0.0.1", 443) != KeyV4("10.0.0.1", 80));
}

// An IPv6 address that differs only in its LAST byte must still produce a
// different key: the key has to cover all 16 address bytes, not just the
// family/port prefix.
HY_TEST(AddrKey_DistinctIPv6TailByte)
{
    uint8_t a[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t b[16];
    std::memcpy(b, a, 16);
    b[15] = 2; // differs only in the final byte
    HY_CHECK(KeyV6(a, 443) != KeyV6(b, 443));

    // ...and in the first byte, and somewhere in the middle.
    uint8_t c[16];
    std::memcpy(c, a, 16);
    c[0] = 0x21;
    HY_CHECK(KeyV6(a, 443) != KeyV6(c, 443));

    uint8_t d[16];
    std::memcpy(d, a, 16);
    d[8] = 0xff;
    HY_CHECK(KeyV6(a, 443) != KeyV6(d, 443));

    // Different port on the same IPv6 address.
    HY_CHECK(KeyV6(a, 443) != KeyV6(a, 80));
}

// IPv4 and IPv6 must not collide with each other.
HY_TEST(AddrKey_FamiliesDoNotCollide)
{
    uint8_t v6[16] = {0};
    // 0.0.0.1 as an IPv4-mapped-ish pattern: make the IPv6 bytes match what a
    // naive byte-wise hash of a sockaddr_in's address field would see.
    v6[12] = 192;
    v6[13] = 0;
    v6[14] = 2;
    v6[15] = 7;
    HY_CHECK(KeyV4("192.0.2.7", 443) != KeyV6(v6, 443));
}

// sin_zero is padding and must not affect the key: the old implementation
// hashed it, which made the key depend on uninitialised bytes whenever a
// caller left them dirty.
HY_TEST(AddrKey_IgnoresIPv4Padding)
{
    struct sockaddr_in clean{};
    clean.sin_family = AF_INET;
    clean.sin_port = htons(443);
    inet_pton(AF_INET, "203.0.113.9", &clean.sin_addr);

    struct sockaddr_in dirty = clean;
    std::memset(dirty.sin_zero, 0xAB, sizeof(dirty.sin_zero));

    HY_CHECK_EQ(AddrKeyForTest(reinterpret_cast<const struct sockaddr*>(&clean), sizeof(clean)),
                AddrKeyForTest(reinterpret_cast<const struct sockaddr*>(&dirty), sizeof(dirty)));
}

// No collisions across a spread of realistic peers.
HY_TEST(AddrKey_NoCollisionsAcrossManyPeers)
{
    std::set<uint64_t> keys;
    constexpr int kCount = 512;

    for (int i = 0; i < kCount; ++i) {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(static_cast<uint16_t>(1024 + i));
        // Spread across 203.0.113.0/24 and a couple of octets.
        const uint8_t bytes[4] = {203, 0, static_cast<uint8_t>(113 + (i / 256)),
                                  static_cast<uint8_t>(i % 256)};
        std::memcpy(&sa.sin_addr, bytes, 4);
        keys.insert(AddrKeyForTest(reinterpret_cast<const struct sockaddr*>(&sa), sizeof(sa)));
    }
    HY_CHECK_EQ(keys.size(), static_cast<size_t>(kCount));

    // Same for IPv6, varying only the low byte of the address.
    keys.clear();
    for (int i = 0; i < 256; ++i) {
        uint8_t addr[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        addr[15] = static_cast<uint8_t>(i);
        keys.insert(KeyV6(addr, 443));
    }
    HY_CHECK_EQ(keys.size(), static_cast<size_t>(256));
}

#endif // HY2_WITH_QUIC_BACKEND