#pragma once
// Lock-wait diagnostics for the hot path. Usage:
//     hy2::diag::LockTimer _lt("stream.writeMu_");
//     std::lock_guard<std::mutex> lk(writeMu_);
//     _lt.done();
// Anything that waited 200 ms or more gets one line in the log (stderr, which
// the GUI redirects into pack\logs\gui.log). The cap keeps a pathological loop
// from flooding the log.
//
// M2: timing is gated on a cached flag. Every lock/unlock pair used to read
// steady_clock::now() twice unconditionally (~30-80 ns each), whether
// diagnostics were wanted or not. Release builds now default to OFF; set
// HY2_LOCK_DIAG=1 to enable (Debug builds default to ON, HY2_LOCK_DIAG=0
// disables). All the diagnostic branches share a cached static, so the
// disabled path costs one relaxed load + branch per lock site.
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace hy2::diag {

inline std::atomic<int> gLockDiagLines{0};
// -1 = not initialised, 0 = off, 1 = on (guarded by getenv on first use).
inline std::atomic<int> gLockDiagMode{-1};
// Test hook: number of steady_clock::now() calls made by LockTimer. Only
// touched when diagnostics are enabled, so it cannot hide a regression in
// the disabled path.
inline std::atomic<unsigned long long> gLockTimerClockReads{0};

inline bool LockDiagEnabled() {
    int m = gLockDiagMode.load(std::memory_order_relaxed);
    if (m < 0) {
        const char* v = std::getenv("HY2_LOCK_DIAG");
        if (v) {
            m = (std::strcmp(v, "0") != 0) ? 1 : 0;
        } else {
#ifdef NDEBUG
            m = 0;  // Release default: no timing on the hot path
#else
            m = 1;  // Debug default: keep the diagnostics
#endif
        }
        gLockDiagMode.store(m, std::memory_order_relaxed);
    }
    return m != 0;
}

// Test-only override; pass -1 to re-apply the environment default.
inline void SetLockDiagEnabledForTest(int mode) {
    gLockDiagMode.store(mode, std::memory_order_relaxed);
}

inline void ReportLockWait(const char* name, long long micros) {
    if (micros < 200000) return;
    if (gLockDiagLines.fetch_add(1) > 20000) return;
    std::fprintf(stderr, "[lock] %s waited %lld ms\n", name, micros / 1000);
    std::fflush(stderr);
}

struct LockTimer {
    const char* name;
    std::chrono::steady_clock::time_point t0;
    bool armed;

    explicit LockTimer(const char* n) : name(n), armed(LockDiagEnabled()) {
        if (armed) {
            t0 = std::chrono::steady_clock::now();
            gLockTimerClockReads.fetch_add(1, std::memory_order_relaxed);
        }
    }
    void done() const {
        if (!armed) return;
        gLockTimerClockReads.fetch_add(1, std::memory_order_relaxed);
        ReportLockWait(name, std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now() - t0).count());
    }
};

}  // namespace hy2::diag
