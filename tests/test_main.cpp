// test_main.cpp - Test runner with results summary and auto-wait.
// Usage: hy2_tests [--no-wait | -y]

#include "hytest.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>

int main(int argc, char* argv[]) {
    bool noWait = false;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--no-wait") == 0 || std::strcmp(argv[i], "-y") == 0) {
            noWait = true;
        }
    }

    int result = hytest::RunAll();

    if (!noWait) {
        std::printf("\nTest finished. Waiting 30 seconds before exit...\n");
        std::fflush(stdout);
        std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    return result;
}
