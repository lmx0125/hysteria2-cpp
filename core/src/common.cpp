// common.cpp - implementation of common.hpp helpers.
#include "hy2/common.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <random>

#ifdef _WIN32
#include <windows.h>
#else
#include <thread>
#endif

namespace hy2 {

MonoTime MonoTime::Now() {
    using namespace std::chrono;
    return MonoTime(duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

void SleepFor(Duration d) {
    if (d.ns <= 0) return;
#ifdef _WIN32
    Sleep(static_cast<DWORD>(d.ns / 1000000LL));
#else
    std::this_thread::sleep_for(std::chrono::nanoseconds(d.ns));
#endif
}

namespace {
// Per-thread generator, seeded once from a shared source. The lock is taken
// only inside the thread_local initializer - i.e. on a thread's first draw -
// rather than on every call as it used to be. That mattered because
// RandomBytes draws once per byte, so the old version took a process-wide
// mutex hundreds of times per obfuscated packet.
std::mt19937_64& GlobalRng() {
    static std::mutex mu;
    static std::mt19937_64 seeder{std::random_device{}()};
    thread_local std::mt19937_64 tlsRng = [&] {
        std::lock_guard<std::mutex> lk(mu);
        return std::mt19937_64(seeder());
    }();
    return tlsRng;
}
} // namespace

uint64_t RandomUint64() { return GlobalRng()(); }

uint32_t RandomUint32() { return static_cast<uint32_t>(GlobalRng()()); }

void RandomBytes(uint8_t* buf, size_t len) {
    // One 64-bit draw per 8 bytes instead of one draw (and one 8-bit slice)
    // per byte.
    auto& rng = GlobalRng();
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        const uint64_t v = rng();
        std::memcpy(buf + i, &v, sizeof(v));
    }
    if (i < len) {
        const uint64_t v = rng();
        std::memcpy(buf + i, &v, len - i);
    }
}

} // namespace hy2
