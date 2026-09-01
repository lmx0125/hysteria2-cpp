#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <optional>
#include <functional>
#include <chrono>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <cstdint>
#include <array>

namespace hy2 {

struct DnsResult {
    std::string address;     // resolved IP address as string
    uint16_t    port = 0;    // original port (for reference)
    bool        isIPv6 = false;
    int         family = 0;  // AF_INET or AF_INET6
};

class DnsResolver {
public:
    // cacheTtl: seconds to cache DNS results (default 300)
    // timeoutMs: timeout for getaddrinfo in milliseconds (default 5000)
    // happyEyeballs: enable IPv4/IPv6 racing (default true)
    explicit DnsResolver(
        uint32_t cacheTtl = 300,
        uint32_t timeoutMs = 5000,
        bool happyEyeballs = true);

    ~DnsResolver();

    // Resolve hostname to IP addresses
    // Returns list of addresses, sorted by preference (IPv6 first if happy eyeballs)
    std::vector<DnsResult> Resolve(const std::string& host, uint16_t port = 0) const;

    // Resolve to a single address (returns first/best)
    std::optional<DnsResult> ResolveOne(const std::string& host, uint16_t port = 0) const;

    // Check if host is already an IP address (no DNS needed)
    static bool IsIpAddress(const std::string& host);

    // Parse IP address string into family + bytes
    static std::optional<std::pair<int, std::array<uint8_t, 16>>>
    ParseIpAddress(const std::string& ip);

    // Clear the DNS cache
    void ClearCache();

    // Get cache statistics
    size_t CacheSize() const;

private:
    uint32_t cacheTtl_;
    uint32_t timeoutMs_;
    bool     happyEyeballs_;

    // DNS cache
    mutable std::mutex cacheMutex_;
    struct CacheEntry {
        std::vector<DnsResult> results;
        std::chrono::steady_clock::time_point expiry;
    };
    mutable std::unordered_map<std::string, CacheEntry> cache_;

    // Core resolution using getaddrinfo
    std::vector<DnsResult> ResolveInternal(const std::string& host, uint16_t port) const;

    // Happy Eyeballs: race IPv4 and IPv6
    std::vector<DnsResult> ResolveHappyEyeballs(const std::string& host, uint16_t port) const;

    // Single-family resolution
    std::vector<DnsResult> ResolveFamily(
        const std::string& host, uint16_t port, int family) const;

    // Check if host matches cache
    std::optional<std::vector<DnsResult>> GetCached(const std::string& host) const;
    void SetCache(const std::string& host, const std::vector<DnsResult>& results) const;
};

} // namespace hy2
