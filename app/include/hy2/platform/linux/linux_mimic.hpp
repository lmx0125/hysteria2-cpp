// linux_mimic.hpp - Linux mimic implementation.
// Uses external mimic binary (XDP/BPF) for packet rewriting.
#pragma once

#ifdef __linux__

#include "hy2/platform/platform_common.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace hy2::platform::linux_impl {

// LinuxMimicInstance - Running mimic process handle.
class LinuxMimicInstance : public IMimicInstance {
public:
    LinuxMimicInstance();
    ~LinuxMimicInstance() override;

    // Start mimic process.
    bool Start(const MimicConfig& cfg,
               MimicRole role,
               const std::vector<std::string>& addresses,
               std::function<void(const std::string&)> logFunc,
               std::function<void(const std::string&)> onExit);

    void Close() override;

private:
    void waitLoop(std::function<void(const std::string&)> onExit);
    void pipeLogs(void* pipe, std::function<void(const std::string&)> logFunc);

    void* processHandle_ = nullptr;  // HANDLE
    void* threadHandle_ = nullptr;   // HANDLE
    std::atomic<bool> running_{false};
    std::atomic<bool> stopped_{false};
};

} // namespace hy2::platform::linux_impl

#endif // __linux__
