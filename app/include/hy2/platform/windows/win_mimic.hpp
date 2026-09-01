// win_mimic.hpp - Windows mimic implementation.
// User-mode fallback that disguises UDP as TCP without kernel acceleration.
// Provides equivalent functionality to Linux XDP/BPF mimic.
#pragma once

#ifdef _WIN32

#include "hy2/platform/platform_common.hpp"

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace hy2::platform::windows_impl {

// WindowsMimicInstance - User-mode packet rewriting.
// Since Windows doesn't have XDP/BPF, this implements the same functional
// goal (disguise UDP as TCP) using user-mode packet manipulation.
class WindowsMimicInstance : public IMimicInstance {
public:
    WindowsMimicInstance();
    ~WindowsMimicInstance() override;

    bool Start(const MimicConfig& cfg,
               MimicRole role,
               const std::vector<std::string>& addresses,
               std::function<void(const std::string&)> logFunc,
               std::function<void(const std::string&)> onExit);

    void Close() override;

private:
    void captureLoop(std::function<void(const std::string&)> logFunc);

    std::atomic<bool> running_{false};
    std::atomic<bool> stopped_{false};
    std::thread captureThread_;
    void* winDivertHandle_ = nullptr;
};

} // namespace hy2::platform::windows_impl

#endif // _WIN32
