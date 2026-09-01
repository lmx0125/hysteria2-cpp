// hytest.hpp - Minimal single-header test harness for hy2 tests.
#pragma once

#include <cmath>
#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
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

inline int RunAll() {
    size_t failed = 0;
    for (const auto& t : Registry()) {
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
    }
    std::printf("\n========================================\n");
    std::printf("  Total:     %zu test(s)\n", Registry().size());
    std::printf("  Passed:    %zu\n", Registry().size() - failed);
    std::printf("  Failed:    %zu\n", failed);
    std::printf("  Result:    %s\n", failed == 0 ? "ALL PASSED" : "HAS FAILURES");
    std::printf("========================================\n");
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
