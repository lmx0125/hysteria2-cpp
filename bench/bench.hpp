// bench.hpp - Minimal benchmark harness for hy2 performance measurement.
// Provides timing, iteration control, and result reporting for microbenchmarks.
#pragma once

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <numeric>
#include <string>
#include <vector>

namespace hybench {

using Clock = std::chrono::high_resolution_clock;
using TimePoint = Clock::time_point;
using Duration = std::chrono::nanoseconds;

struct Result {
    std::string name;
    int64_t iterations = 0;
    double totalMs = 0.0;
    double minNs = 0.0;
    double maxNs = 0.0;
    double meanNs = 0.0;
    double medianNs = 0.0;
    double p95Ns = 0.0;
    double p99Ns = 0.0;
    double opsPerSec = 0.0;
    double mbPerSec = 0.0;
    size_t bytesPerOp = 0;

    void Print() const {
        std::printf("  %-40s %8.1f ns/op  %10.0f ops/s", name.c_str(), meanNs, opsPerSec);
        if (mbPerSec > 0.0) {
            std::printf("  %8.2f MB/s", mbPerSec);
        }
        std::printf("\n");
        std::printf("    min=%8.1f  max=%8.1f  p95=%8.1f  p99=%8.1f  median=%8.1f  iters=%ld\n",
                     minNs, maxNs, p95Ns, p99Ns, medianNs, (long)iterations);
    }
};

class BenchRunner {
public:
    struct BenchCase {
        std::string name;
        std::function<void()> fn;
        size_t bytesPerOp;
    };

    static std::vector<BenchCase>& Registry() {
        static std::vector<BenchCase> r;
        return r;
    }

    static int Register(const char* name, std::function<void()> fn, size_t bpo = 0) {
        Registry().push_back({name, std::move(fn), bpo});
        return 0;
    }

    // Warmup + timed iterations. Returns a Result.
    static Result Run(const BenchCase& bc, int warmupIters = 2000, int measureIters = 5000) {
        // Warmup
        for (int i = 0; i < warmupIters; ++i) {
            bc.fn();
        }

        // Measure
        std::vector<double> times;
        times.reserve(measureIters);

        auto wallStart = Clock::now();
        for (int i = 0; i < measureIters; ++i) {
            auto t0 = Clock::now();
            bc.fn();
            auto t1 = Clock::now();
            times.push_back(static_cast<double>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count()));
        }
        auto wallEnd = Clock::now();

        // Sort for percentile calculation
        std::sort(times.begin(), times.end());

        Result r;
        r.name = bc.name;
        r.iterations = measureIters;
        r.bytesPerOp = bc.bytesPerOp;
        r.totalMs = std::chrono::duration<double, std::milli>(wallEnd - wallStart).count();
        r.minNs = times.front();
        r.maxNs = times.back();
        r.meanNs = 0.0;
        for (auto t : times) r.meanNs += t;
        r.meanNs /= static_cast<double>(measureIters);
        r.medianNs = times[measureIters / 2];
        r.p95Ns = times[static_cast<size_t>(measureIters * 0.95)];
        r.p99Ns = times[static_cast<size_t>(measureIters * 0.99)];
        r.opsPerSec = (r.meanNs > 0.0) ? 1e9 / r.meanNs : 0.0;
        if (bc.bytesPerOp > 0 && r.meanNs > 0.0) {
            r.mbPerSec = static_cast<double>(bc.bytesPerOp) / r.meanNs;
        }
        return r;
    }

    static int RunAll() {
        int failed = 0;
        std::vector<Result> results;
        std::printf("\n========================================\n");
        std::printf("  hy2-cpp Performance Benchmarks\n");
        std::printf("========================================\n\n");

        for (const auto& bc : Registry()) {
            std::printf("[BENCH] %s\n", bc.name.c_str());
            std::fflush(stdout);
            try {
                auto r = Run(bc);
                r.Print();
                results.push_back(std::move(r));
            } catch (const std::exception& e) {
                failed++;
                std::printf("[FAIL ] %s: %s\n", bc.name.c_str(), e.what());
            }
            std::fflush(stdout);
        }

        // Summary
        std::printf("\n========================================\n");
        std::printf("  Summary: %zu benchmarks, %d failed\n", results.size(), failed);
        std::printf("========================================\n");

        return failed == 0 ? 0 : 1;
    }
};

} // namespace hybench

#define HY_BENCH(name, bytesPerOp)                                           \
    static void hy_bench_##name();                                           \
    static int hy_bench_reg_##name =                                         \
        ::hybench::BenchRunner::Register(#name, &hy_bench_##name, bytesPerOp); \
    static void hy_bench_##name()

#define HY_BENCH_NOSize(name)                                                \
    static void hy_bench_##name();                                           \
    static int hy_bench_reg_##name =                                         \
        ::hybench::BenchRunner::Register(#name, &hy_bench_##name, 0);        \
    static void hy_bench_##name()
