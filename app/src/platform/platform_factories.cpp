// platform_factories.cpp - Platform-specific factory functions.
// Creates the appropriate implementation based on the current platform.

#include "hy2/platform/platform_common.hpp"

#ifdef __linux__
#include "hy2/platform/linux/linux_tproxy.hpp"
#include "hy2/platform/linux/linux_redirector.hpp"
#include "hy2/platform/linux/linux_tun.hpp"
#include "hy2/platform/linux/linux_firewall.hpp"
#include "hy2/platform/linux/linux_mimic.hpp"
#endif

#ifdef _WIN32
#include "hy2/platform/windows/win_tproxy.hpp"
#include "hy2/platform/windows/win_redirector.hpp"
#include "hy2/platform/windows/win_tun.hpp"
#include "hy2/platform/windows/win_firewall.hpp"
#include "hy2/platform/windows/win_mimic.hpp"
#endif

namespace hy2::platform {

// ---------------------------------------------------------------------------
// TUN device factory

std::unique_ptr<ITunDevice> CreateTunDevice(const TunConfig& config) {
#ifdef __linux__
    return std::make_unique<linux_impl::LinuxTunDevice>(config);
#elif defined(_WIN32)
    return std::make_unique<windows_impl::WindowsTunDevice>(config);
#else
    return nullptr;
#endif
}

// ---------------------------------------------------------------------------
// Destination getter factory

std::unique_ptr<IDestGetter> CreateDestGetter() {
    // Platform-specific implementation
    // For now, return nullptr (to be implemented)
    return nullptr;
}

// ---------------------------------------------------------------------------
// Transparent proxy factories

std::unique_ptr<ITransparentProxy> CreateTcpTransparentProxy(
    TcpDialFunc dialFunc,
    std::shared_ptr<ITransparentProxyEventLogger> logger) {
#ifdef __linux__
    return std::make_unique<linux_impl::LinuxTcpTProxy>(std::move(dialFunc), std::move(logger));
#elif defined(_WIN32)
    return std::make_unique<windows_impl::WindowsTcpTransparentProxy>(std::move(dialFunc), std::move(logger));
#else
    return nullptr;
#endif
}

std::unique_ptr<ITransparentProxy> CreateUdpTransparentProxy(
    UdpDialFunc dialFunc,
    std::shared_ptr<ITransparentProxyEventLogger> logger,
    uint32_t timeoutMs) {
#ifdef __linux__
    return std::make_unique<linux_impl::LinuxUdpTProxy>(std::move(dialFunc), std::move(logger), timeoutMs);
#elif defined(_WIN32)
    return std::make_unique<windows_impl::WindowsUdpTransparentProxy>(std::move(dialFunc), std::move(logger), timeoutMs);
#else
    return nullptr;
#endif
}

// ---------------------------------------------------------------------------
// Redirector factory

std::unique_ptr<IRedirector> CreateTcpRedirector(
    TcpDialFunc dialFunc,
    std::shared_ptr<IRedirectorEventLogger> logger) {
#ifdef __linux__
    return std::make_unique<linux_impl::LinuxTcpRedirector>(std::move(dialFunc), std::move(logger));
#elif defined(_WIN32)
    return std::make_unique<windows_impl::WindowsTcpRedirector>(std::move(dialFunc), std::move(logger));
#else
    return nullptr;
#endif
}

// ---------------------------------------------------------------------------
// Firewall manager factory

std::unique_ptr<IFirewallManager> CreateFirewallManager() {
#ifdef __linux__
    return std::make_unique<linux_impl::LinuxFirewallManager>();
#elif defined(_WIN32)
    return std::make_unique<windows_impl::WindowsFirewallManager>();
#else
    return nullptr;
#endif
}

// ---------------------------------------------------------------------------
// Mimic factory

std::shared_ptr<IMimicInstance> StartMimic(
    const MimicConfig& cfg,
    MimicRole role,
    const std::vector<std::string>& addresses,
    std::function<void(const std::string&)> logFunc,
    std::function<void(const std::string&)> onExit) {
    if (!cfg.Enabled) return nullptr;

#ifdef __linux__
    auto instance = std::make_shared<linux_impl::LinuxMimicInstance>();
    if (instance->Start(cfg, role, addresses, std::move(logFunc), std::move(onExit))) {
        return instance;
    }
    return nullptr;
#elif defined(_WIN32)
    auto instance = std::make_shared<windows_impl::WindowsMimicInstance>();
    if (instance->Start(cfg, role, addresses, std::move(logFunc), std::move(onExit))) {
        return instance;
    }
    return nullptr;
#else
    return nullptr;
#endif
}

} // namespace hy2::platform
