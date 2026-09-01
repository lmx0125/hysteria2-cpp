// test_main_full.cpp - Unified test runner for all hy2 test suites.
// Links all test object files into a single executable.
//
// Usage: hy2_full_test.exe [options] [filter]
//   No args:            run all tests
//   filter:             run only tests matching the prefix (case-insensitive)
//   -h, --help:         show help and available prefixes
//   -y, --no-wait:      skip 30s wait after tests complete
//
// Examples:
//   hy2_full_test.exe                   # run all, wait 30s
//   hy2_full_test.exe -y                # run all, exit immediately
//   hy2_full_test.exe platform          # run platform tests only
//   hy2_full_test.exe -y frag           # run frag tests, no wait

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
    std::printf("  -y, --no-wait:      skip 30s wait after tests complete\n");
    std::printf("  -h, --help:         show this help and available prefixes\n");
    std::printf("\nExamples:\n");
    std::printf("  %s                    # run all tests\n", prog);
    std::printf("  %s -y                 # run all, exit immediately\n", prog);
    std::printf("  %s platform           # run platform tests only\n", prog);
    std::printf("  %s -y frag            # run frag tests, no wait\n", prog);
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

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            showHelp = true;
        } else if (std::strcmp(argv[i], "-y") == 0 || std::strcmp(argv[i], "--no-wait") == 0) {
            noWait = true;
        } else {
            filter = argv[i];
        }
    }

    if (showHelp) {
        printUsage(argv[0]);
        return 0;
    }

    int result = 0;

    if (filter) {
        // Filtered run
        size_t failed = 0;
        size_t run = 0;
        std::string prefix(filter);

        for (const auto& t : hytest::Registry()) {
            std::string name(t.name);
            // Match prefix: "platform" matches "PlatformMimic_..." and "PlatformFactory_..."
            if (name.find(prefix) != 0) {
                // Also check case-insensitive prefix match after first underscore
                auto underscore = name.find('_');
                if (underscore != std::string::npos) {
                    std::string testPrefix = name.substr(0, underscore);
                    // Case-insensitive compare
                    std::string lowerPrefix = prefix;
                    for (auto& c : lowerPrefix) c = static_cast<char>(std::tolower(c));
                    std::string lowerTest = testPrefix;
                    for (auto& c : lowerTest) c = static_cast<char>(std::tolower(c));
                    if (lowerTest.find(lowerPrefix) == std::string::npos) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            run++;
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
        std::printf("  Filter:    %s\n", filter);
        std::printf("  Total:     %zu/%zu test(s)\n", run, hytest::Registry().size());
        std::printf("  Passed:    %zu\n", run - failed);
        std::printf("  Failed:    %zu\n", failed);
        std::printf("  Result:    %s\n", failed == 0 ? "ALL PASSED" : "HAS FAILURES");
        std::printf("========================================\n");
        result = (failed == 0) ? 0 : 1;
    } else {
        // Run all
        result = hytest::RunAll();
    }

    if (!noWait) {
        std::printf("\nWaiting 30 seconds before exit... (use -y to skip)\n");
        std::fflush(stdout);
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    return result;
}
