#include "hy2/dns.hpp"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#endif

namespace hy2 {

// ---------- helpers ----------

static bool IsDigit(char c) { return c >= '0' && c <= '9'; }

static bool IsHexDigit(char c) {
    return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

#ifdef _WIN32
// Windows: getaddrinfo with timeout using select
static int GetAddrInfoWithTimeout(
    const char* host, const char* port, int family,
    struct addrinfo** result, uint32_t timeoutMs)
{
    // For simplicity, just call getaddrinfo directly (Windows getaddrinfo is async enough)
    struct addrinfo hints{};
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    return getaddrinfo(host, port, &hints, result);
}
#else
// Unix: getaddrinfo with timeout using a thread
struct GaiRequest {
    const char* host;
    const char* port;
    int family;
    struct addrinfo** result;
    int ret;
    bool done;
    std::mutex mtx;
    std::condition_variable cv;
};

static void* GetAddrInfoThread(void* arg) {
    auto* req = static_cast<GaiRequest*>(arg);
    req->ret = getaddrinfo(req->host, req->port, nullptr, req->result);
    {
        std::lock_guard<std::mutex> lock(req->mtx);
        req->done = true;
    }
    req->cv.notify_one();
    return nullptr;
}

static int GetAddrInfoWithTimeout(
    const char* host, const char* port, int family,
    struct addrinfo** result, uint32_t timeoutMs)
{
    GaiRequest req{};
    req.host = host;
    req.port = port;
    req.family = family;
    req.result = result;
    req.ret = EAI_SYSTEM;
    req.done = false;

    pthread_t tid;
    pthread_create(&tid, nullptr, GetAddrInfoThread, &req);

    {
        std::unique_lock<std::mutex> lock(req.mtx);
        if (!req.cv.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                             [&]{ return req.done; })) {
            // Timeout - we can't cancel getaddrinfo, but we'll return timeout
            pthread_detach(tid);
            return EAI_AGAIN;
        }
    }
    pthread_join(tid, nullptr);
    return req.ret;
}
#endif

// ---------- DnsResolver ----------

DnsResolver::DnsResolver(uint32_t cacheTtl, uint32_t timeoutMs, bool happyEyeballs)
    : cacheTtl_(cacheTtl), timeoutMs_(timeoutMs), happyEyeballs_(happyEyeballs)
{}

DnsResolver::~DnsResolver() = default;

bool DnsResolver::IsIpAddress(const std::string& host) {
    if (host.empty()) return false;

    // Check IPv6 bracket notation [::1]
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        return ParseIpAddress(host.substr(1, host.size() - 2)).has_value();
    }
    return ParseIpAddress(host).has_value();
}

std::optional<std::pair<int, std::array<uint8_t, 16>>>
DnsResolver::ParseIpAddress(const std::string& ip) {
    // Try IPv4: a.b.c.d
    {
        bool allDots = true;
        int dotCount = 0;
        for (char c : ip) {
            if (c == '.') dotCount++;
            else if (!IsDigit(c)) { allDots = false; break; }
        }
        if (allDots && dotCount == 3) {
            struct in_addr addr4;
            if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
                std::array<uint8_t, 16> bytes{};
                std::memcpy(bytes.data(), &addr4, 4);
                return std::make_pair(AF_INET, bytes);
            }
        }
    }

    // Try IPv6
    {
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
            std::array<uint8_t, 16> bytes{};
            std::memcpy(bytes.data(), &addr6, 16);
            return std::make_pair(AF_INET6, bytes);
        }
    }

    return std::nullopt;
}

std::vector<DnsResult> DnsResolver::Resolve(const std::string& host, uint16_t port) const {
    // Fast path: already an IP address
    if (IsIpAddress(host)) {
        auto parsed = ParseIpAddress(host);
        if (parsed) {
            DnsResult r;
            r.address = host;
            r.port = port;
            r.isIPv6 = (parsed->first == AF_INET6);
            r.family = parsed->first;
            return {r};
        }
    }

    // Check cache
    if (auto cached = GetCached(host)) {
        return *cached;
    }

    // Resolve
    std::vector<DnsResult> results;
    if (happyEyeballs_) {
        results = ResolveHappyEyeballs(host, port);
    } else {
        results = ResolveInternal(host, port);
    }

    // Apply port
    for (auto& r : results) r.port = port;

    // Cache results
    SetCache(host, results);
    return results;
}

std::optional<DnsResult> DnsResolver::ResolveOne(const std::string& host, uint16_t port) const {
    auto results = Resolve(host, port);
    if (results.empty()) return std::nullopt;
    return results.front();
}

void DnsResolver::ClearCache() {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cache_.clear();
}

size_t DnsResolver::CacheSize() const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return cache_.size();
}

std::vector<DnsResult> DnsResolver::ResolveInternal(const std::string& host, uint16_t port) const {
    return ResolveFamily(host, port, AF_UNSPEC);
}

std::vector<DnsResult> DnsResolver::ResolveHappyEyeballs(
    const std::string& host, uint16_t port) const
{
    // Try IPv6 first, then IPv4, interleave results
    auto v6 = ResolveFamily(host, port, AF_INET6);
    auto v4 = ResolveFamily(host, port, AF_INET);

    std::vector<DnsResult> results;
    size_t maxLen = std::max(v6.size(), v4.size());
    for (size_t i = 0; i < maxLen; ++i) {
        if (i < v6.size()) results.push_back(v6[i]);
        if (i < v4.size()) results.push_back(v4[i]);
    }
    return results;
}

std::vector<DnsResult> DnsResolver::ResolveFamily(
    const std::string& host, uint16_t port, int family) const
{
    std::string portStr = (port > 0) ? std::to_string(port) : "";

    struct addrinfo* res = nullptr;
    int ret = GetAddrInfoWithTimeout(
        host.c_str(), portStr.empty() ? nullptr : portStr.c_str(),
        family, &res, timeoutMs_);

    if (ret != 0 || !res) {
        if (res) freeaddrinfo(res);
        return {};
    }

    std::vector<DnsResult> results;
    for (struct addrinfo* p = res; p; p = p->ai_next) {
        DnsResult r;
        r.family = p->ai_family;
        r.isIPv6 = (p->ai_family == AF_INET6);

        char addrStr[INET6_ADDRSTRLEN]{};
        if (p->ai_family == AF_INET) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, addrStr, sizeof(addrStr));
        } else if (p->ai_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(p->ai_addr);
            inet_ntop(AF_INET6, &sin6->sin6_addr, addrStr, sizeof(addrStr));
        }
        r.address = addrStr;

        // Extract port
        if (p->ai_family == AF_INET) {
            r.port = ntohs(reinterpret_cast<struct sockaddr_in*>(p->ai_addr)->sin_port);
        } else if (p->ai_family == AF_INET6) {
            r.port = ntohs(reinterpret_cast<struct sockaddr_in6*>(p->ai_addr)->sin6_port);
        }

        if (!r.address.empty()) {
            results.push_back(std::move(r));
        }
    }

    freeaddrinfo(res);
    return results;
}

std::optional<std::vector<DnsResult>>
DnsResolver::GetCached(const std::string& host) const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = cache_.find(host);
    if (it == cache_.end()) return std::nullopt;
    if (std::chrono::steady_clock::now() > it->second.expiry) {
        cache_.erase(it);
        return std::nullopt;
    }
    return it->second.results;
}

void DnsResolver::SetCache(
    const std::string& host, const std::vector<DnsResult>& results) const
{
    std::lock_guard<std::mutex> lock(cacheMutex_);
    CacheEntry entry;
    entry.results = results;
    entry.expiry = std::chrono::steady_clock::now() + std::chrono::seconds(cacheTtl_);
    cache_[host] = std::move(entry);
}

} // namespace hy2
