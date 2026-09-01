// acl_engine.cpp - ACL rule engine matching Go's extras/outbounds/acl format.
// Rewrite of extras/outbounds/acl/parse.go + compile.go + acl.go.
#include "hy2/outbounds/acl_engine.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
#endif

namespace hy2::outbounds {

namespace {

std::string toLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end = s.find_last_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

// Parse "start-end" port range
bool parsePortRange(const std::string& s, AclPortRange& range) {
    auto dash = s.find('-');
    if (dash == std::string::npos) {
        // Single port
        int port = std::atoi(s.c_str());
        if (port < 0 || port > 65535) return false;
        range.start = static_cast<uint16_t>(port);
        range.end = range.start;
        return true;
    }
    int start = std::atoi(s.substr(0, dash).c_str());
    int end = std::atoi(s.substr(dash + 1).c_str());
    if (start < 0 || start > 65535 || end < 0 || end > 65535) return false;
    range.start = static_cast<uint16_t>(start);
    range.end = static_cast<uint16_t>(end);
    return true;
}

// Try to parse as IPv4 or IPv6
bool isIPv4(const std::string& s) {
    struct in_addr addr{};
    return inet_pton(AF_INET, s.c_str(), &addr) == 1;
}

bool isIPv6(const std::string& s) {
    struct in6_addr addr{};
    return inet_pton(AF_INET6, s.c_str(), &addr) == 1;
}

// Wildcard domain match: *.example.com matches foo.example.com, bar.example.com
bool wildcardMatch(const std::string& pattern, const std::string& host) {
    // pattern is like "*.example.com"
    if (pattern.empty() || pattern[0] != '*') return false;
    std::string suffix = pattern.substr(1); // ".example.com"
    if (suffix.empty()) return false;
    if (host.size() < suffix.size()) return false;
    std::string hostSuffix = host.substr(host.size() - suffix.size());
    if (hostSuffix != suffix) return false;
    // Check that there's at least one character before the suffix
    return host.size() > suffix.size();
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Parsing

bool AclEngine::parseRule(const std::string& line, AclRule& rule) {
    // Format: outbound(address) or outbound(address,protoPort) or
    //         outbound(address,protoPort,hijackAddress)
    std::string s = trim(line);
    if (s.empty() || s[0] == '#') return false;

    // Find opening paren
    auto openParen = s.find('(');
    if (openParen == std::string::npos) return false;

    // Extract outbound name
    rule.outboundName = trim(s.substr(0, openParen));

    // Find closing paren
    auto closeParen = s.rfind(')');
    if (closeParen == std::string::npos || closeParen <= openParen + 1) return false;

    // Extract arguments
    std::string args = s.substr(openParen + 1, closeParen - openParen - 1);

    // Split by comma (max 3 parts)
    std::vector<std::string> parts;
    std::istringstream iss(args);
    std::string part;
    while (std::getline(iss, part, ',')) {
        parts.push_back(trim(part));
    }

    if (parts.empty() || parts[0].empty()) return false;

    // First arg: address matcher
    if (!parseAddress(parts[0], rule.addressMatcher)) return false;

    // Second arg: proto/port (optional)
    if (parts.size() >= 2 && !parts[1].empty()) {
        if (!parseProtoPort(parts[1], rule.proto, rule.portRange)) return false;
    }

    // Third arg: hijack address (optional)
    if (parts.size() >= 3 && !parts[2].empty()) {
        rule.hijackAddress = parts[2];
    }

    return true;
}

bool AclEngine::parseAddress(const std::string& addr, AclAddressMatcher& matcher) {
    matcher.raw = addr;

    // * or all → All matcher
    if (addr == "*" || addr == "all") {
        matcher.type = AclRuleType::All;
        return true;
    }

    // geoip:XX (placeholder)
    if (addr.substr(0, 7) == "geoip:") {
        matcher.type = AclRuleType::GeoIp;
        matcher.domain = addr.substr(7);
        return true;
    }

    // geosite:name (placeholder)
    if (addr.substr(0, 8) == "geosite:") {
        matcher.type = AclRuleType::GeoSite;
        matcher.domain = addr.substr(8);
        return true;
    }

    // suffix:example.com
    if (addr.substr(0, 7) == "suffix:") {
        matcher.type = AclRuleType::DomainSuffix;
        matcher.domain = toLower(addr.substr(7));
        return true;
    }

    // .example.com (suffix shorthand)
    if (addr[0] == '.') {
        matcher.type = AclRuleType::DomainSuffix;
        matcher.domain = toLower(addr);
        return true;
    }

    // CIDR: x.x.x.x/n or xxxx::/n
    auto slash = addr.find('/');
    if (slash != std::string::npos) {
        std::string ipPart = addr.substr(0, slash);
        int prefix = std::atoi(addr.substr(slash + 1).c_str());

        if (isIPv4(ipPart)) {
            struct in_addr addr4{};
            inet_pton(AF_INET, ipPart.c_str(), &addr4);
            std::memcpy(matcher.cidrAddr, &addr4, 4);
            matcher.cidrPrefix = prefix;
            matcher.type = AclRuleType::Cidr4;
            return true;
        }
        if (isIPv6(ipPart)) {
            struct in6_addr addr6{};
            inet_pton(AF_INET6, ipPart.c_str(), &addr6);
            std::memcpy(matcher.cidrAddr, &addr6, 16);
            matcher.cidrPrefix = prefix;
            matcher.type = AclRuleType::Cidr6;
            return true;
        }
        return false;
    }

    // Exact IP
    if (isIPv4(addr)) {
        struct in_addr addr4{};
        inet_pton(AF_INET, addr.c_str(), &addr4);
        std::memcpy(matcher.cidrAddr, &addr4, 4);
        matcher.type = AclRuleType::Ip4;
        return true;
    }
    if (isIPv6(addr)) {
        struct in6_addr addr6{};
        inet_pton(AF_INET6, addr.c_str(), &addr6);
        std::memcpy(matcher.cidrAddr, &addr6, 16);
        matcher.type = AclRuleType::Ip6;
        return true;
    }

    // Wildcard domain: *.example.com
    if (addr[0] == '*') {
        matcher.type = AclRuleType::DomainWildcard;
        matcher.domain = toLower(addr);
        return true;
    }

    // Exact domain
    matcher.type = AclRuleType::DomainExact;
    matcher.domain = toLower(addr);
    return true;
}

bool AclEngine::parseProtoPort(const std::string& pp, AclProto& proto, AclPortRange& port) {
    // Format: "tcp", "udp", "tcp/80", "tcp/80-443", "*/80", "80"
    proto = AclProto::Both;
    port = {0, 65535};

    auto slash = pp.find('/');
    std::string protoPart = (slash != std::string::npos) ? pp.substr(0, slash) : pp;
    std::string portPart = (slash != std::string::npos) ? pp.substr(slash + 1) : "";

    // Parse protocol
    if (protoPart == "tcp" || protoPart == "TCP") {
        proto = AclProto::TCP;
    } else if (protoPart == "udp" || protoPart == "UDP") {
        proto = AclProto::UDP;
    } else if (protoPart == "*" || protoPart.empty()) {
        proto = AclProto::Both;
    } else {
        return false;
    }

    // Parse port
    if (!portPart.empty() && portPart != "*") {
        if (!parsePortRange(portPart, port)) return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Matching

bool AclEngine::matchAddress(const AclAddressMatcher& matcher, const std::string& host) {
    std::string hostLower = toLower(host);

    switch (matcher.type) {
    case AclRuleType::All:
        return true;

    case AclRuleType::Ip4: {
        struct in_addr host4{};
        if (inet_pton(AF_INET, host.c_str(), &host4) != 1) return false;
        return std::memcmp(matcher.cidrAddr, &host4, 4) == 0;
    }
    case AclRuleType::Ip6: {
        struct in6_addr host6{};
        if (inet_pton(AF_INET6, host.c_str(), &host6) != 1) return false;
        return std::memcmp(matcher.cidrAddr, &host6, 16) == 0;
    }
    case AclRuleType::Cidr4: {
        struct in_addr host4{};
        if (inet_pton(AF_INET, host.c_str(), &host4) != 1) return false;
        // Apply mask and compare
        uint32_t mask = matcher.cidrPrefix == 0 ? 0
            : (~0u) << (32 - matcher.cidrPrefix);
        uint32_t hostNet = ntohl(host4.s_addr);
        uint32_t ruleNet = ntohl(reinterpret_cast<const struct in_addr*>(matcher.cidrAddr)->s_addr);
        return (hostNet & mask) == (ruleNet & mask);
    }
    case AclRuleType::Cidr6: {
        struct in6_addr host6{};
        if (inet_pton(AF_INET6, host.c_str(), &host6) != 1) return false;
        // Apply mask and compare
        int fullBytes = matcher.cidrPrefix / 8;
        int remainingBits = matcher.cidrPrefix % 8;
        if (fullBytes > 0 && std::memcmp(matcher.cidrAddr, &host6, fullBytes) != 0) return false;
        if (remainingBits > 0 && fullBytes < 16) {
            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remainingBits));
            if ((matcher.cidrAddr[fullBytes] & mask) != (host6.s6_addr[fullBytes] & mask))
                return false;
        }
        return true;
    }
    case AclRuleType::DomainSuffix:
        return hostLower == matcher.domain ||
               (hostLower.size() > matcher.domain.size() &&
                hostLower.substr(hostLower.size() - matcher.domain.size()) == matcher.domain);

    case AclRuleType::DomainWildcard:
        return wildcardMatch(matcher.domain, hostLower);

    case AclRuleType::DomainExact:
        return hostLower == matcher.domain;

    case AclRuleType::GeoIp:
    case AclRuleType::GeoSite:
        // Placeholder: not yet implemented
        return false;
    }
    return false;
}

bool AclEngine::matchPort(const AclPortRange& range, uint16_t port) {
    return port >= range.start && port <= range.end;
}

bool AclEngine::splitHostPort(const std::string& addr, std::string& host, uint16_t& port) {
    // Handle IPv6: [::1]:80
    if (!addr.empty() && addr[0] == '[') {
        auto closeBracket = addr.find(']');
        if (closeBracket == std::string::npos) return false;
        host = addr.substr(1, closeBracket - 1);
        if (closeBracket + 1 < addr.size() && addr[closeBracket + 1] == ':') {
            port = static_cast<uint16_t>(std::atoi(addr.c_str() + closeBracket + 2));
        }
        return true;
    }
    auto colon = addr.rfind(':');
    if (colon == std::string::npos) return false;
    host = addr.substr(0, colon);
    port = static_cast<uint16_t>(std::atoi(addr.c_str() + colon + 1));
    return true;
}

// ---------------------------------------------------------------------------
// ACL Engine

void AclEngine::Parse(const std::string& aclText) {
    rules_.clear();
    std::istringstream iss(aclText);
    std::string line;
    while (std::getline(iss, line)) {
        AclRule rule;
        if (parseRule(line, rule)) {
            rules_.push_back(std::move(rule));
        }
    }
}

void AclEngine::RegisterOutbound(const std::string& name, std::shared_ptr<server::Outbound> ob) {
    outbounds_[name] = std::move(ob);
}

void AclEngine::SetDefaultOutbound(std::shared_ptr<server::Outbound> ob) {
    defaultOutbound_ = std::move(ob);
}

std::shared_ptr<server::Outbound> AclEngine::Evaluate(
    const std::string& host, uint16_t port, AclProto proto,
    std::string* hijackAddr) {

    for (const auto& rule : rules_) {
        // Check protocol
        if (rule.proto != AclProto::Both && rule.proto != proto) continue;

        // Check port
        if (!matchPort(rule.portRange, port)) continue;

        // Check address
        if (!matchAddress(rule.addressMatcher, host)) continue;

        // Match found
        if (hijackAddr && !rule.hijackAddress.empty()) {
            *hijackAddr = rule.hijackAddress;
        }

        // Built-in "reject" always returns nullptr (blocks traffic)
        if (rule.outboundName == "reject") return nullptr;

        // Built-in "direct" → use default outbound
        if (rule.outboundName == "direct") return defaultOutbound_;

        // "default" → use default outbound
        if (rule.outboundName == "default") return defaultOutbound_;

        // User-registered outbound
        auto it = outbounds_.find(rule.outboundName);
        if (it != outbounds_.end()) return it->second;

        return nullptr;
    }

    // No rule matched → use default outbound
    return defaultOutbound_;
}

std::shared_ptr<server::IConn> AclEngine::TCP(const std::string& reqAddr) {
    std::string host;
    uint16_t port = 0;
    if (!splitHostPort(reqAddr, host, port)) {
        throw std::runtime_error("invalid address: " + reqAddr);
    }

    std::string hijackAddr;
    auto ob = Evaluate(host, port, AclProto::TCP, &hijackAddr);
    if (!ob) {
        throw std::runtime_error("connection rejected by ACL");
    }

    std::string targetAddr = hijackAddr.empty()
        ? reqAddr
        : hijackAddr + ":" + std::to_string(port);

    return ob->TCP(targetAddr);
}

std::shared_ptr<server::IUdpConn> AclEngine::UDP(const std::string& reqAddr) {
    std::string host;
    uint16_t port = 0;
    if (!splitHostPort(reqAddr, host, port)) {
        throw std::runtime_error("invalid address: " + reqAddr);
    }

    std::string hijackAddr;
    auto ob = Evaluate(host, port, AclProto::UDP, &hijackAddr);
    if (!ob) {
        throw std::runtime_error("connection rejected by ACL");
    }

    std::string targetAddr = hijackAddr.empty()
        ? reqAddr
        : hijackAddr + ":" + std::to_string(port);

    return ob->UDP(targetAddr);
}

bool AclEngine::CheckUDP(const std::string& reqAddr) {
    std::string host;
    uint16_t port = 0;
    if (!splitHostPort(reqAddr, host, port)) return false;
    auto ob = Evaluate(host, port, AclProto::UDP);
    return ob != nullptr;
}

} // namespace hy2::outbounds
