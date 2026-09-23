// test_main_full.cpp - Unified test runner for all hy2 test suites.
// Links all test object files into a single executable.
//
// Usage: hy2_full_test.exe [options] [filter]
//   No args:            run all tests
//   filter:             run only tests matching the prefix (case-insensitive)
//   -t, --timeout <s>:  per-test wall-clock budget in seconds (default 60)
//   -h, --help:         show help and available prefixes
//   -y, --no-wait:      skip 30s wait after tests complete
//
// Examples:
//   hy2_full_test.exe                   # run all, wait 30s
//   hy2_full_test.exe -y                # run all, exit immediately
//   hy2_full_test.exe platform          # run platform tests only
//   hy2_full_test.exe -y -t 10 frag     # frag tests, 10s budget each
//
// A test that exceeds its budget is reported as TIMEOUT and the run moves on
// to the next test. Because a hung worker thread cannot be joined, the
// process exits with std::_Exit(1) after printing the summary.

#include "hytest.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

static void printUsage(const char* prog) {
    std::printf("Usage: %s [options] [filter]\n", prog);
    std::printf("  No args:            run all tests, wait 30s before exit\n");
    std::printf("  filter:             run only tests matching the prefix\n");
    std::printf("  -t, --timeout <s>:  per-test budget in seconds (default 60)\n");
    std::printf("  -y, --no-wait:      skip 30s wait after tests complete\n");
    std::printf("  -h, --help:         show this help and available prefixes\n");
    std::printf("\nExamples:\n");
    std::printf("  %s                    # run all tests\n", prog);
    std::printf("  %s -y                 # run all, exit immediately\n", prog);
    std::printf("  %s platform           # run platform tests only\n", prog);
    std::printf("  %s -y -t 10 frag      # frag tests, 10s budget each\n", prog);
    std::printf("\nAvailable test prefixes (from registry):\n");

    // Collect unique prefixes
    std::vector<std::string> prefixes;
    for (const auto& t : hytest::Registry()) {
        std::string name(t.name);
        auto underscore = name.find('_');
        if (underscore != std::string::npos) {
            std::string prefix = name.substr(0, underscore);
            bool found = false;
            for (const auto& p : prefixes) {
                if (p == prefix) { found = true; break; }
            }
            if (!found) prefixes.push_back(prefix);
        }
    }
    for (const auto& p : prefixes) {
        std::printf("    %s\n", p.c_str());
    }
}

int main(int argc, char* argv[]) {
    const char* filter = nullptr;
    bool showHelp = false;
    bool noWait = false;
    int timeoutSec = 60;
    std::vector<std::string> skips;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            showHelp = true;
        } else if (std::strcmp(argv[i], "-y") == 0 || std::strcmp(argv[i], "--no-wait") == 0) {
            noWait = true;
        } else if ((std::strcmp(argv[i], "-t") == 0 || std::strcmp(argv[i], "--timeout") == 0) &&
                   i + 1 < argc) {
            timeoutSec = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--skip") == 0 && i + 1 < argc) {
            skips.emplace_back(argv[++i]);
        } else {
            filter = argv[i];
        }
    }

    if (showHelp) {
        printUsage(argv[0]);
        return 0;
    }

    const std::chrono::seconds budget(timeoutSec > 0 ? timeoutSec : 0);
    int result = 0;

    auto matchPrefix = [](const std::string& name, const std::string& prefix) {
        if (name.find(prefix) == 0) return true;
        auto underscore = name.find('_');
        if (underscore == std::string::npos) return false;
        std::string testPrefix = name.substr(0, underscore);
        std::string lowerPrefix = prefix, lowerTest = testPrefix;
        for (auto& c : lowerPrefix) c = static_cast<char>(std::tolower(c));
        for (auto& c : lowerTest) c = static_cast<char>(std::tolower(c));
        return lowerTest.find(lowerPrefix) != std::string::npos;
    };

    if (filter || !skips.empty()) {
        // Filtered run (with optional --skip prefixes)
        size_t failed = 0;
        size_t run = 0;
        bool anyTimeout = false;
        std::string prefix(filter ? filter : std::string());

        for (const auto& t : hytest::Registry()) {
            std::string name(t.name);
            if (filter && !matchPrefix(name, prefix)) continue;
            bool skipped = false;
            for (const auto& s : skips) {
                if (matchPrefix(name, s)) { skipped = true; break; }
            }
            if (skipped) continue;

            run++;
            bool timedOut = false;
            if (budget.count() > 0) {
                if (!hytest::RunOnePrinted(t, budget, timedOut)) failed++;
            } else {
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
            }
            if (timedOut) anyTimeout = true;
        }

        std::printf("\n========================================\n");
        std::printf("  Filter:    %s\n", prefix.empty() ? "(all)" : prefix.c_str());
        std::printf("  Total:     %zu/%zu test(s)\n", run, hytest::Registry().size());
        std::printf("  Passed:    %zu\n", run - failed);
        std::printf("  Failed:    %zu\n", failed);
        std::printf("  Result:    %s\n", failed == 0 ? "ALL PASSED" : "HAS FAILURES");
        std::printf("========================================\n");
        std::fflush(stdout);
        result = (failed == 0) ? 0 : 1;
        if (anyTimeout) {
            // Detached worker threads cannot be joined; skip static destructors.
            std::_Exit(result);
        }
    } else {
        // Run all
        result = hytest::RunAllTimed(budget);
    }

    if (!noWait) {
        std::printf("\nWaiting 30 seconds before exit... (use -y to skip)\n");
        std::fflush(stdout);
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    return result;
}
