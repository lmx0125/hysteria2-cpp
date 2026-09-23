#include "hy2/acl.hpp"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <cctype>

namespace hy2 {

// ---------- helpers ----------

static int HexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse dotted-decimal IPv4 string into 4 bytes. Returns false on error.
//
// Hand-rolled rather than istringstream + stoi: each of those constructs a
// locale-bearing stream object and allocates a token string, and this runs for
// every IP/CIDR ACL rule on every connection. The acceptance rules are
// unchanged, including the lenient handling of a trailing ".5".
static bool ParseIPv4Bytes(const std::string& s, uint8_t out[4]) {
    size_t pos = 0;
    for (int i = 0; i < 4; ++i) {
        if (i > 0) {
            if (pos >= s.size() || s[pos] != '.') return false;
            ++pos;
        }
        const size_t start = pos;
        int val = 0;
        while (pos < s.size() && s[pos] != '.') {
            const char c = s[pos];
            if (c < '0' || c > '9') return false;
            val = val * 10 + (c - '0');
            ++pos;
            if (pos - start > 3) return false;
        }
        if (pos == start) return false; // empty token
        if (val > 255) return false;
        out[i] = static_cast<uint8_t>(val);
    }
    return true;
}

// Expand IPv6 string to 16 bytes (host order). Supports :: expansion.
// Simplified but covers common cases.
static bool ParseIPv6Bytes(const std::string& s, uint8_t out[16]) {
    if (s.empty()) return false;
    std::string str = s;

    // Find :: expansion
    auto dblColon = str.find("::");
    if (dblColon != std::string::npos) {
        std::string left  = str.substr(0, dblColon);
        std::string right = str.substr(dblColon + 2);
        std::vector<std::string> parts;
        if (!left.empty()) {
            std::istringstream lis(left);
            std::string tok;
            while (std::getline(lis, tok, ':')) parts.push_back(tok);
        }
        std::vector<std::string> rparts;
        if (!right.empty()) {
            std::istringstream ris(right);
            std::string tok;
            while (std::getline(ris, tok, ':')) rparts.push_back(tok);
        }
        int groups = static_cast<int>(parts.size() + rparts.size());
        if (groups > 7) return false;
        int zeros = 8 - groups;
        std::vector<std::string> expanded;
        for (auto& p : parts) expanded.push_back(p);
        for (int i = 0; i < zeros; ++i) expanded.push_back("0");
        for (auto& p : rparts) expanded.push_back(p);
        if (expanded.size() != 8) return false;

        for (int i = 0; i < 8; ++i) {
            if (expanded[i].size() > 4) return false;
            unsigned long val = std::stoul(expanded[i], nullptr, 16);
            if (val > 0xFFFF) return false;
            out[i * 2]     = static_cast<uint8_t>((val >> 8) & 0xFF);
            out[i * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
        }
        return true;
    }

    // No :: - split by ':'
    std::istringstream iss(str);
    std::string tok;
    std::vector<std::string> parts;
    while (std::getline(iss, tok, ':')) parts.push_back(tok);
    if (parts.size() != 8) return false;
    for (int i = 0; i < 8; ++i) {
        if (parts[i].size() > 4) return false;
        unsigned long val = std::stoul(parts[i], nullptr, 16);
        if (val > 0xFFFF) return false;
        out[i * 2]     = static_cast<uint8_t>((val >> 8) & 0xFF);
        out[i * 2 + 1] = static_cast<uint8_t>(val & 0xFF);
    }
    return true;
}

// Convert IPv4 to IPv4-mapped IPv6 (::ffff:a.b.c.d)
static void Ipv4ToMapped(const uint8_t ip4[4], uint8_t out[16]) {
    std::memset(out, 0, 10);
    out[10] = 0xFF;
    out[11] = 0xFF;
    std::memcpy(out + 12, ip4, 4);
}

// Mask a 128-bit address
static void MaskAddress(uint8_t addr[16], uint8_t bits) {
    for (int i = 0; i < 16; ++i) {
        if (bits >= 8) { bits -= 8; continue; }
        if (bits == 0) { addr[i] = 0; continue; }
        uint8_t mask = (uint8_t)(0xFF << (8 - bits));
        addr[i] &= mask;
        bits = 0;
    }
}

// Lowercase a string
static std::string ToLower(std::string s) {
    for (auto& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// Trim whitespace from both ends
static std::string Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// ---------- ParseCidr / ParseIpAddress ----------

std::optional<std::tuple<std::array<uint8_t,16>, uint8_t, uint8_t>>
ParseCidr(const std::string& cidr) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return std::nullopt;

    std::string addrStr = cidr.substr(0, slash);
    std::string bitsStr = cidr.substr(slash + 1);

    // Try IPv4 first
    uint8_t ip4[4];
    if (ParseIPv4Bytes(addrStr, ip4)) {
        int bits = std::stoi(bitsStr);
        if (bits < 0 || bits > 32) return std::nullopt;
        std::array<uint8_t,16> addr{};
        std::memcpy(addr.data(), ip4, 4);
        MaskAddress(addr.data(), bits);
        return std::make_tuple(addr, (uint8_t)bits, (uint8_t)4);
    }

    // Try IPv6
    uint8_t ip6[16];
    if (ParseIPv6Bytes(addrStr, ip6)) {
        int bits = std::stoi(bitsStr);
        if (bits < 0 || bits > 128) return std::nullopt;
        std::array<uint8_t,16> addr{};
        std::memcpy(addr.data(), ip6, 16);
        MaskAddress(addr.data(), bits);
        return std::make_tuple(addr, (uint8_t)bits, (uint8_t)16);
    }

    return std::nullopt;
}

std::optional<std::tuple<std::array<uint8_t,16>, uint8_t>>
ParseIpAddress(const std::string& ip) {
    // Handle IPv4-mapped IPv6: ::ffff:1.2.3.4
    if (ip.substr(0, 7) == "::ffff:" && ip.find('.') != std::string::npos) {
        std::string ipv4Part = ip.substr(7);
        uint8_t ip4[4];
        if (ParseIPv4Bytes(ipv4Part, ip4)) {
            std::array<uint8_t,16> addr{};
            // ::ffff:x.x.x.x = 00 00 00 00 00 00 00 00 00 00 ff ff x.x.x.x
            addr[10] = 0xFF;
            addr[11] = 0xFF;
            std::memcpy(addr.data() + 12, ip4, 4);
            return std::make_tuple(addr, (uint8_t)16);
        }
    }

    uint8_t ip4[4];
    if (ParseIPv4Bytes(ip, ip4)) {
        std::array<uint8_t,16> addr{};
        std::memcpy(addr.data(), ip4, 4);
        return std::make_tuple(addr, (uint8_t)4);
    }
    uint8_t ip6[16];
    if (ParseIPv6Bytes(ip, ip6)) {
        std::array<uint8_t,16> addr{};
        std::memcpy(addr.data(), ip6, 16);
        return std::make_tuple(addr, (uint8_t)16);
    }
    return std::nullopt;
}

// ---------- AclRule ----------

bool AclRule::MatchesIp4(const uint8_t* ip4) const {
    if (type == AclRuleType::Ipv4) {
        return std::memcmp(ip4, addr, 4) == 0;
    }
    if (type == AclRuleType::Ipv4Cidr && cidrBits <= 32) {
        uint8_t masked[4];
        std::memcpy(masked, ip4, 4);
        uint8_t maskBits = cidrBits;
        for (int i = 0; i < 4; ++i) {
            if (maskBits >= 8) { maskBits -= 8; continue; }
            if (maskBits == 0) { masked[i] = 0; continue; }
            uint8_t m = (uint8_t)(0xFF << (8 - maskBits));
            masked[i] &= m;
            maskBits = 0;
        }
        return std::memcmp(masked, cidrAddr, 4) == 0;
    }
    return false;
}

bool AclRule::MatchesIp6(const uint8_t* ip6) const {
    if (type == AclRuleType::Ipv6) {
        return std::memcmp(ip6, addr, 16) == 0;
    }
    if (type == AclRuleType::Ipv6Cidr && cidrBits <= 128) {
        uint8_t masked[16];
        std::memcpy(masked, ip6, 16);
        MaskAddress(masked, cidrBits);
        return std::memcmp(masked, cidrAddr, 16) == 0;
    }
    // Check if IPv6 is actually an IPv4-mapped address and rule is IPv4
    if (ip6[0]==0 && ip6[1]==0 && ip6[2]==0 && ip6[3]==0 &&
        ip6[4]==0 && ip6[5]==0 && ip6[6]==0 && ip6[7]==0 &&
        ip6[8]==0 && ip6[9]==0 && ip6[10]==0xFF && ip6[11]==0xFF) {
        if (type == AclRuleType::Ipv4) {
            return std::memcmp(ip6 + 12, addr, 4) == 0;
        }
        if (type == AclRuleType::Ipv4Cidr && cidrBits <= 32) {
            uint8_t masked[4];
            std::memcpy(masked, ip6 + 12, 4);
            uint8_t maskBits = cidrBits;
            for (int i = 0; i < 4; ++i) {
                if (maskBits >= 8) { maskBits -= 8; continue; }
                if (maskBits == 0) { masked[i] = 0; continue; }
                uint8_t m = (uint8_t)(0xFF << (8 - maskBits));
                masked[i] &= m;
                maskBits = 0;
            }
            return std::memcmp(masked, cidrAddr, 4) == 0;
        }
    }
    return false;
}

bool AclRule::MatchesDomain(const std::string& name) const {
    if (type == AclRuleType::DomainKeyword) {
        // Case-insensitive substring match
        std::string lowerName = ToLower(name);
        std::string lowerDomain = ToLower(domain);
        return lowerName.find(lowerDomain) != std::string::npos;
    }
    if (type == AclRuleType::DomainSuffix) {
        // Case-insensitive suffix match: name must equal domain or end with ".domain"
        std::string lowerName = ToLower(name);
        std::string lowerDomain = ToLower(domain);
        if (lowerName == lowerDomain) return true;
        if (lowerName.size() > lowerDomain.size() + 1) {
            std::string suffix = lowerName.substr(lowerName.size() - lowerDomain.size() - 1);
            return suffix == "." + lowerDomain;
        }
        return false;
    }
    return false;
}

// ---------- Acl ----------

Acl::Acl(AclAction defaultAction) : defaultAction_(defaultAction) {}

void Acl::AddRule(AclRule rule) {
    rules_.push_back(std::move(rule));
}

AclAction Acl::DefaultAction() const {
    return defaultAction_;
}

size_t Acl::RuleCount() const {
    return rules_.size();
}

void Acl::Clear() {
    rules_.clear();
}

AclAction Acl::EvaluateIp4(const uint8_t* ip4, uint16_t port) const {
    // Find highest-priority matching rule
    int bestPriority = -1;
    AclAction bestAction = defaultAction_;
    for (const auto& rule : rules_) {
        if (rule.MatchesIp4(ip4)) {
            if (rule.priority >= bestPriority) {
                bestPriority = rule.priority;
                bestAction = rule.action;
            }
        }
    }
    return bestAction;
}

AclAction Acl::EvaluateIp6(const uint8_t* ip6, uint16_t port) const {
    int bestPriority = -1;
    AclAction bestAction = defaultAction_;
    for (const auto& rule : rules_) {
        if (rule.MatchesIp6(ip6)) {
            if (rule.priority >= bestPriority) {
                bestPriority = rule.priority;
                bestAction = rule.action;
            }
        }
    }
    return bestAction;
}

AclAction Acl::Evaluate(const std::string& host, uint16_t port) const {
    // Try IP parse first
    auto ipResult = ParseIpAddress(host);
    if (ipResult) {
        auto [addr, addrLen] = *ipResult;
        if (addrLen == 4) return EvaluateIp4(addr.data(), port);
        if (addrLen == 16) return EvaluateIp6(addr.data(), port);
    }

    // Domain matching - try all rules
    int bestPriority = -1;
    AclAction bestAction = defaultAction_;
    for (const auto& rule : rules_) {
        if (rule.MatchesDomain(host)) {
            if (rule.priority >= bestPriority) {
                bestPriority = rule.priority;
                bestAction = rule.action;
            }
        }
    }
    return bestAction;
}

Acl Acl::Parse(const std::string& aclText, AclAction defaultAction) {
    Acl acl(defaultAction);
    std::istringstream iss(aclText);
    std::string line;

    while (std::getline(iss, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;

        // Parse: "action host[/port]"
        std::istringstream lss(line);
        std::string actionStr, hostPart;
        if (!(lss >> actionStr >> hostPart)) continue;

        AclAction action;
        if (actionStr == "allow" || actionStr == "a") {
            action = AclAction::Allow;
        } else if (actionStr == "deny" || actionStr == "d") {
            action = AclAction::Deny;
        } else {
            continue;
        }

        // Split host and optional port
        std::string host = hostPart;
        // (port filtering not implemented in this version - would need more context)

        AclRule rule;
        rule.action = action;
        rule.priority = 0;

        // Try CIDR
        auto cidr = ParseCidr(host);
        if (cidr) {
            auto [addr, bits, addrLen] = *cidr;
            if (addrLen == 4) {
                rule.type = AclRuleType::Ipv4Cidr;
                rule.cidrBits = bits;
                std::memcpy(rule.cidrAddr, addr.data(), 4);
            } else {
                rule.type = AclRuleType::Ipv6Cidr;
                rule.cidrBits = bits;
                std::memcpy(rule.cidrAddr, addr.data(), 16);
            }
            acl.AddRule(std::move(rule));
            continue;
        }

        // Try IP literal
        auto ip = ParseIpAddress(host);
        if (ip) {
            auto [addr, addrLen] = *ip;
            if (addrLen == 4) {
                rule.type = AclRuleType::Ipv4;
                rule.addrLen = 4;
                std::memcpy(rule.addr, addr.data(), 4);
            } else {
                rule.type = AclRuleType::Ipv6;
                rule.addrLen = 16;
                std::memcpy(rule.addr, addr.data(), 16);
            }
            acl.AddRule(std::move(rule));
            continue;
        }

        // Domain rules: prefix with "." for suffix, bare for keyword
        if (host.size() > 1 && host[0] == '.') {
            rule.type = AclRuleType::DomainSuffix;
            rule.domain = host.substr(1);
            acl.AddRule(std::move(rule));
            continue;
        }

        // Check for wildcard patterns like "*example.com" (treated as keyword)
        if (host.size() > 1 && host[0] == '*') {
            rule.type = AclRuleType::DomainKeyword;
            rule.domain = host.substr(1);
            acl.AddRule(std::move(rule));
            continue;
        }

        // Default: domain keyword match
        rule.type = AclRuleType::DomainKeyword;
        rule.domain = host;
        acl.AddRule(std::move(rule));
    }

    return acl;
}

} // namespace hy2
