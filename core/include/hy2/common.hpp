// common.hpp - Shared fundamental types for hy2 (Hysteria 2 C++ rewrite).
// Mirrors quic-go's congestion/monotime types used by the original Go code.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace hy2 {

// ByteCount is like quic-go's congestion.ByteCount.
using ByteCount = int64_t;

// PacketNumber is like quic-go's congestion.PacketNumber.
using PacketNumber = int64_t;

// Monotonic time in nanoseconds. Mirrors monotime.Time (which counts
// nanoseconds from an arbitrary origin). Zero value == "not set".
struct MonoTime {
    int64_t ns = 0;

    MonoTime() = default;
    explicit constexpr MonoTime(int64_t nanos) : ns(nanos) {}

    static MonoTime Now(); // steady clock

    constexpr bool IsZero() const { return ns == 0; }

    constexpr MonoTime Add(int64_t deltaNs) const { return MonoTime(ns + deltaNs); }
    constexpr int64_t Sub(MonoTime o) const { return ns - o.ns; }

    friend constexpr bool operator<(MonoTime a, MonoTime b) { return a.ns < b.ns; }
    friend constexpr bool operator<=(MonoTime a, MonoTime b) { return a.ns <= b.ns; }
    friend constexpr bool operator>(MonoTime a, MonoTime b) { return a.ns > b.ns; }
    friend constexpr bool operator>=(MonoTime a, MonoTime b) { return a.ns >= b.ns; }
    friend constexpr bool operator==(MonoTime a, MonoTime b) { return a.ns == b.ns; }
    friend constexpr bool operator!=(MonoTime a, MonoTime b) { return a.ns != b.ns; }
};

// Duration in nanoseconds.
struct Duration {
    int64_t ns = 0;

    constexpr Duration() = default;
    explicit constexpr Duration(int64_t nanos) : ns(nanos) {}

    static constexpr Duration FromSeconds(double s) { return Duration(static_cast<int64_t>(s * 1e9)); }
    static constexpr Duration FromMillis(int64_t ms) { return Duration(ms * 1000000); }
    static constexpr Duration FromNanos(int64_t n) { return Duration(n); }

    constexpr double Seconds() const { return static_cast<double>(ns) / 1e9; }
    constexpr int64_t Milliseconds() const { return ns / 1000000; }

    friend constexpr Duration operator+(Duration a, Duration b) { return Duration(a.ns + b.ns); }
    friend constexpr Duration operator-(Duration a, Duration b) { return Duration(a.ns - b.ns); }
    friend constexpr bool operator<(Duration a, Duration b) { return a.ns < b.ns; }
    friend constexpr bool operator<=(Duration a, Duration b) { return a.ns <= b.ns; }
    friend constexpr bool operator>(Duration a, Duration b) { return a.ns > b.ns; }
    friend constexpr bool operator>=(Duration a, Duration b) { return a.ns >= b.ns; }
};

constexpr ByteCount kInitialPacketSize = 1350; // congestion.InitialPacketSize in quic-go
constexpr Duration kMinPacingDelay = Duration::FromMillis(1); // congestion.MinPacingDelay

// Sleep for the given duration.
void SleepFor(Duration d);

// Random source helpers (thread-safe).
uint64_t RandomUint64();
uint32_t RandomUint32();
// Fill buf with pseudo-random bytes (non-cryptographic; mirrors math/rand usage).
void RandomBytes(uint8_t* buf, size_t len);

} // namespace hy2
