// test_main.cpp - Test runner with results summary and auto-wait.
// Usage: <test_exe> [--timeout <sec>] [--no-wait | -y]
//
// Every test runs on its own worker thread with a hard wall-clock budget
// (default 60s). A hung test is reported as TIMEOUT and the run continues;
// the process then exits hard because the detached worker cannot be joined.

#include "hytest.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

int main(int argc, char* argv[]) {
    bool noWait = false;
    int timeoutSec = 60;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--no-wait") == 0 || std::strcmp(argv[i], "-y") == 0) {
            noWait = true;
        } else if ((std::strcmp(argv[i], "--timeout") == 0 ||
                    std::strcmp(argv[i], "-t") == 0) && i + 1 < argc) {
            timeoutSec = std::atoi(argv[++i]);
        }
    }

    int result = hytest::RunAllTimed(std::chrono::seconds(timeoutSec > 0 ? timeoutSec : 0));

    if (!noWait) {
        std::printf("\nTest finished. Waiting 30 seconds before exit...\n");
        std::fflush(stdout);
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    return result;
}
