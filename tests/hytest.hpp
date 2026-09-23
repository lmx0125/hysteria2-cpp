// hytest.hpp - Minimal single-header test harness for hy2 tests.
#pragma once

#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace hytest {

struct TestCase {
    const char* name;
    void (*fn)();
};

inline std::vector<TestCase>& Registry() {
    static std::vector<TestCase> r;
    return r;
}

inline bool Register(const char* name, void (*fn)()) {
    Registry().push_back(TestCase{name, fn});
    return true;
}

// How a single test finished. kTimeout means the worker thread never returned
// within the budget: it is detached and the run continues with the next test.
enum class TestOutcome { kPassed, kFailed, kTimeout };

struct TestResult {
    TestOutcome outcome = TestOutcome::kFailed;
    std::string error;      // failure message (kFailed only)
    long long elapsedMs = 0;
};

// Runs one test on its own thread with a hard wall-clock budget. A hung test
// (blocked socket/condvar/deadlock) can be neither killed nor joined in C++,
// so it is detached and the process must not run static destructors after a
// timeout - callers must use std::_Exit() once any test timed out.
inline TestResult RunOneTimed(const TestCase& t, std::chrono::seconds timeout) {
    TestResult result;
    std::mutex m;
    std::condition_variable cv;
    bool done = false;
    bool passed = false;
    std::string error;

    const auto started = std::chrono::steady_clock::now();
    std::thread worker([&] {
        try {
            t.fn();
            passed = true;
        } catch (const std::exception& e) {
            error = e.what();
        } catch (...) {
            error = "unknown exception";
        }
        {
            std::lock_guard<std::mutex> lk(m);
            done = true;
        }
        cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lk(m);
        if (!cv.wait_for(lk, timeout, [&] { return done; })) {
            result.outcome = TestOutcome::kTimeout;
            result.elapsedMs = timeout.count() * 1000;
            worker.detach();
            return result;
        }
    }
    worker.join();
    result.elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - started).count();
    if (passed) {
        result.outcome = TestOutcome::kPassed;
    } else {
        result.outcome = TestOutcome::kFailed;
        result.error = error;
    }
    return result;
}

// Runs a single test and prints the [ RUN ]/[ OK ]/[FAIL ] lines.
// Returns true when the test passed (timeout counts as failure).
inline bool RunOnePrinted(const TestCase& t, std::chrono::seconds timeout,
                          bool& timedOut, long long* elapsedMs = nullptr) {
    std::printf("[ RUN ] %s\n", t.name);
    std::fflush(stdout);
    TestResult r = RunOneTimed(t, timeout);
    timedOut = r.outcome == TestOutcome::kTimeout;
    if (elapsedMs) *elapsedMs = r.elapsedMs;
    if (r.outcome == TestOutcome::kPassed) {
        std::printf("[  OK ] %s (%lld ms)\n", t.name, r.elapsedMs);
    } else if (r.outcome == TestOutcome::kTimeout) {
        std::printf("[FAIL ] %s: TIMEOUT after %lld s (worker thread detached)\n",
                    t.name, r.elapsedMs / 1000);
    } else {
        std::printf("[FAIL ] %s: %s\n", t.name, r.error.c_str());
    }
    std::fflush(stdout);
    return r.outcome == TestOutcome::kPassed;
}

inline int RunAllTimed(std::chrono::seconds timeout);

inline int RunAll() {
    return RunAllTimed(std::chrono::seconds(0));
}

// timeout == 0 disables the per-test budget (legacy behavior).
inline int RunAllTimed(std::chrono::seconds timeout) {
    size_t failed = 0;
    bool anyTimeout = false;
    for (const auto& t : Registry()) {
        if (timeout.count() <= 0) {
            std::printf("[ RUN ] %s\n", t.name);
            std::fflush(stdout);
            try {
                t.fn();
                std::printf("[  OK ] %s\n", t.name);
            } catch (const std::exception& e) {
                failed++;
                std::printf("[FAIL ] %s: %s\n", t.name, e.what());
            } catch (...) {
                failed++;
                std::printf("[FAIL ] %s: unknown exception\n", t.name);
            }
            std::fflush(stdout);
            continue;
        }
        bool timedOut = false;
        if (!RunOnePrinted(t, timeout, timedOut)) failed++;
        if (timedOut) anyTimeout = true;
    }
    std::printf("\n========================================\n");
    std::printf("  Total:     %zu test(s)\n", Registry().size());
    std::printf("  Passed:    %zu\n", Registry().size() - failed);
    std::printf("  Failed:    %zu\n", failed);
    std::printf("  Result:    %s\n", failed == 0 ? "ALL PASSED" : "HAS FAILURES");
    std::printf("========================================\n");
    std::fflush(stdout);
    if (anyTimeout) {
        // A detached worker may hold heap/locks; static destructors could
        // deadlock or crash. Exit hard, keep the already printed summary.
        std::_Exit(1);
    }
    return failed == 0 ? 0 : 1;
}

} // namespace hytest

#define HY_TEST(name)                                                        \
    static void hy_test_##name();                                            \
    static bool hy_reg_##name = ::hytest::Register(#name, &hy_test_##name);  \
    static void hy_test_##name()

#define HY_CHECK(cond)                                                       \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::ostringstream hy_os_;                                       \
            hy_os_ << "check failed at " << __FILE__ << ":" << __LINE__      \
                   << ": " << #cond;                                         \
            throw std::runtime_error(hy_os_.str());                          \
        }                                                                    \
    } while (0)

#define HY_CHECK_EQ(a, b)                                                    \
    do {                                                                     \
        auto hy_va_ = (a);                                                   \
        auto hy_vb_ = (b);                                                   \
        if (!(hy_va_ == hy_vb_)) {                                           \
            std::ostringstream hy_os_;                                       \
            hy_os_ << "check failed at " << __FILE__ << ":" << __LINE__      \
                   << ": " << #a << " == " << #b                             \
                   << " (" << hy_va_ << " vs " << hy_vb_ << ")";             \
            throw std::runtime_error(hy_os_.str());                          \
        }                                                                    \
    } while (0)

#define HY_CHECK_NEAR(a, b, eps)                                             \
    do {                                                                     \
        double hy_va_ = static_cast<double>(a);                              \
        double hy_vb_ = static_cast<double>(b);                              \
        if (!(std::fabs(hy_va_ - hy_vb_) <= (eps))) {                        \
            std::ostringstream hy_os_;                                       \
            hy_os_ << "check failed at " << __FILE__ << ":" << __LINE__      \
                   << ": |" << hy_va_ << " - " << hy_vb_ << "| > " << eps;   \
            throw std::runtime_error(hy_os_.str());                          \
        }                                                                    \
    } while (0)

#define HY_CHECK_THROWS(expr, ExType)                                        \
    do {                                                                     \
        bool hy_threw_ = false;                                              \
        try {                                                                \
            (void)(expr);                                                     \
        } catch (const ExType&) {                                            \
            hy_threw_ = true;                                                \
        } catch (...) {                                                      \
        }                                                                    \
        if (!hy_threw_) {                                                    \
            std::ostringstream hy_os_;                                       \
            hy_os_ << "check failed at " << __FILE__ << ":" << __LINE__      \
                   << ": expected " #ExType;                                 \
            throw std::runtime_error(hy_os_.str());                          \
        }                                                                    \
    } while (0)
