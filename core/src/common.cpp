// common.cpp - implementation of common.hpp helpers.
#include "hy2/common.hpp"

#include <chrono>
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
std::mt19937_64& GlobalRng() {
    static std::mutex mu;
    static std::mt19937_64 rng{std::random_device{}()};
    std::lock_guard<std::mutex> lk(mu);
    thread_local std::mt19937_64 tlsRng{rng()};
    (void)mu;
    return tlsRng;
}
} // namespace

uint64_t RandomUint64() { return GlobalRng()(); }

uint32_t RandomUint32() { return static_cast<uint32_t>(GlobalRng()()); }

void RandomBytes(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) buf[i] = static_cast<uint8_t>(GlobalRng()());
}

} // namespace hy2
