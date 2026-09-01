#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <tuple>
#include <vector>
#include <optional>
#include <variant>

namespace hy2 {

enum class AclAction : uint8_t {
    Allow = 0,
    Deny  = 1,
};

enum class AclRuleType : uint8_t {
    Ipv4Cidr,
    Ipv6Cidr,
    Ipv4,
    Ipv6,
    DomainSuffix,
    DomainKeyword,
};

struct AclRule {
    AclRuleType type;
    AclAction   action;
    int         priority = 0;   // higher = more specific = checked first

    // For Ipv4Cidr / Ipv6Cidr
    uint8_t  cidrAddr[16] = {};   // host-order bytes
    uint8_t  cidrBits     = 0;

    // For Ipv4 / Ipv6
    uint8_t  addr[16] = {};
    uint8_t  addrLen  = 0;        // 4 for IPv4, 16 for IPv6

    // For DomainSuffix / DomainKeyword
    std::string domain;

    bool MatchesIp4(const uint8_t* ip4) const;
    bool MatchesIp6(const uint8_t* ip6) const;
    bool MatchesDomain(const std::string& name) const;
};

class Acl {
public:
    // defaultAction is applied when no rule matches
    Acl(AclAction defaultAction = AclAction::Deny);

    void AddRule(AclRule rule);

    // Returns Allow or Deny
    AclAction Evaluate(const std::string& host, uint16_t port) const;
    AclAction EvaluateIp4(const uint8_t* ip4, uint16_t port) const;
    AclAction EvaluateIp6(const uint8_t* ip6, uint16_t port) const;

    AclAction DefaultAction() const;

    size_t RuleCount() const;

    // Parse acl text. Each line: "action host" or "action host/port"
    // Lines starting with '#' are comments. Blank lines are ignored.
    static Acl Parse(const std::string& aclText, AclAction defaultAction = AclAction::Deny);

    void Clear();

private:
    AclAction              defaultAction_;
    std::vector<AclRule>   rules_;
};

// Utility: parse a CIDR string like "192.168.1.0/24" or "::1/128"
// Returns (addr bytes, bits, addrLen) or nullopt on parse error
std::optional<std::tuple<std::array<uint8_t,16>, uint8_t, uint8_t>>
ParseCidr(const std::string& cidr);

// Utility: parse an IP address string like "192.168.1.1" or "::1"
// Returns (addr bytes, addrLen) or nullopt
std::optional<std::tuple<std::array<uint8_t,16>, uint8_t>>
ParseIpAddress(const std::string& ip);

} // namespace hy2
