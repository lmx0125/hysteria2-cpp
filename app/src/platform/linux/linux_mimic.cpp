// linux_mimic.cpp - Linux mimic implementation.
// Uses external mimic binary (XDP/BPF) for packet rewriting.

#ifdef __linux__

#include "hy2/platform/linux/linux_mimic.hpp"
#include "hy2/platform/mimic_common.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>

namespace hy2::platform::linux_impl {

LinuxMimicInstance::LinuxMimicInstance() {}

LinuxMimicInstance::~LinuxMimicInstance() {
    Close();
}

bool LinuxMimicInstance::Start(const MimicConfig& cfg,
                                MimicRole role,
                                const std::vector<std::string>& addresses,
                                std::function<void(const std::string&)> logFunc,
                                std::function<void(const std::string&)> onExit) {
    if (!cfg.Enabled || addresses.empty()) return false;

    // Generate filters
    auto filters = GenerateMimicFilters(role, addresses);
    if (filters.empty()) return false;

    // Resolve binary path
    std::string binary = cfg.Path;
    if (binary.empty()) {
        binary = "mimic";  // Search in PATH
    }

    // Build command arguments
    std::vector<std::string> args = {"run"};
    if (!cfg.Interface.empty()) {
        args.push_back(cfg.Interface);
    }
    for (const auto& filter : filters) {
        args.push_back("-f");
        args.push_back(filter);
    }
    if (!cfg.XDPMode.empty()) {
        args.push_back("--xdp-mode");
        args.push_back(cfg.XDPMode);
    }
    for (const auto& extra : cfg.ExtraArgs) {
        args.push_back(extra);
    }

    // Create pipe for stderr
    int stderrPipe[2];
    if (pipe(stderrPipe) < 0) return false;

    // Fork and exec
    pid_t pid = fork();
    if (pid < 0) {
        close(stderrPipe[0]);
        close(stderrPipe[1]);
        return false;
    }

    if (pid == 0) {
        // Child process
        close(stderrPipe[0]);
        dup2(stderrPipe[1], STDERR_FILENO);
        close(stderrPipe[1]);

        // Build argv
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(binary.c_str()));
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        execvp(binary.c_str(), argv.data());
        _exit(1);
    }

    // Parent process
    close(stderrPipe[1]);
    processHandle_ = reinterpret_cast<void*>(static_cast<intptr_t>(pid));

    // Start log piping thread
    running_ = true;
    std::thread(&LinuxMimicInstance::pipeLogs, this,
                reinterpret_cast<void*>(static_cast<intptr_t>(stderrPipe[0])),
                logFunc).detach();

    // Start wait thread
    std::thread(&LinuxMimicInstance::waitLoop, this, onExit).detach();

    return true;
}

void LinuxMimicInstance::Close() {
    if (!running_) return;

    stopped_ = true;
    running_ = false;

    if (processHandle_) {
        pid_t pid = static_cast<pid_t>(reinterpret_cast<intptr_t>(processHandle_));
        kill(pid, SIGINT);
        waitpid(pid, nullptr, 0);
        processHandle_ = nullptr;
    }
}

void LinuxMimicInstance::waitLoop(std::function<void(const std::string&)> onExit) {
    if (processHandle_) {
        pid_t pid = static_cast<pid_t>(reinterpret_cast<intptr_t>(processHandle_));
        int status;
        waitpid(pid, &status, 0);

        if (!stopped_ && onExit) {
            onExit("mimic exited unexpectedly");
        }
    }
}

void LinuxMimicInstance::pipeLogs(void* pipe,
                                   std::function<void(const std::string&)> logFunc) {
    int fd = static_cast<int>(reinterpret_cast<intptr_t>(pipe));
    char buf[1024];
    std::string lineBuffer;

    while (true) {
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;

        buf[n] = '\0';
        lineBuffer += buf;

        // Process complete lines
        size_t pos;
        while ((pos = lineBuffer.find('\n')) != std::string::npos) {
            std::string line = lineBuffer.substr(0, pos);
            lineBuffer = lineBuffer.substr(pos + 1);

            // Strip ANSI escape codes
            // Simple approach: skip ESC[ sequences
            std::string clean;
            bool inEscape = false;
            for (char c : line) {
                if (c == '\x1b') {
                    inEscape = true;
                    continue;
                }
                if (inEscape) {
                    if (c >= 'A' && c <= 'Z') inEscape = false;
                    continue;
                }
                clean += c;
            }

            if (!clean.empty() && logFunc) {
                logFunc(clean);
            }
        }
    }

    close(fd);
}

} // namespace hy2::platform::linux_impl

#endif // __linux__
