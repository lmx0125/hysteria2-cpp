// acl_engine.hpp - ACL rule engine matching Go's extras/outbounds/acl format.
// Syntax: outbound(address[,protoPort[,hijackAddress]])
// Supports: direct, reject, default outbounds + user-defined outbounds.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "hy2/server_iface.hpp"

namespace hy2::outbounds {

// ---------------------------------------------------------------------------
// Address matchers

enum class AclRuleType {
    All,            // * or all
    Cidr4,          // IPv4 CIDR
    Cidr6,          // IPv6 CIDR
    Ip4,            // Exact IPv4
    Ip6,            // Exact IPv6
    DomainSuffix,   // suffix:example.com or .example.com
    DomainWildcard, // *.example.com
    DomainExact,    // example.com
    GeoIp,          // geoip:XX (placeholder)
    GeoSite,        // geosite:name (placeholder)
};

struct AclAddressMatcher {
    AclRuleType type;
    std::string raw;           // original string
    uint8_t cidrAddr[16]{};   // for CIDR/IP
    int cidrPrefix = 0;        // for CIDR
    std::string domain;        // for domain matchers
};

// Protocol filter
enum class AclProto : uint8_t {
    Both = 0,
    TCP = 1,
    UDP = 2,
};

struct AclPortRange {
    uint16_t start = 0;
    uint16_t end = 65535;
};

// ---------------------------------------------------------------------------
// ACL rule

struct AclRule {
    std::string outboundName;           // "direct", "reject", "default", or user name
    AclAddressMatcher addressMatcher;
    AclProto proto = AclProto::Both;
    AclPortRange portRange{0, 65535};
    std::string hijackAddress;          // optional IP to rewrite destination
};

// ---------------------------------------------------------------------------
// ACL engine - evaluates rules and dispatches to outbounds

class AclEngine : public server::Outbound {
public:
    // Parse ACL text (one rule per line, # comments).
    void Parse(const std::string& aclText);

    // Register a named outbound. Must be called before Evaluate.
    // "direct", "reject" are built-in (reject returns nullptr).
    void RegisterOutbound(const std::string& name, std::shared_ptr<server::Outbound> ob);

    // Set the default outbound (used when no rule matches).
    void SetDefaultOutbound(std::shared_ptr<server::Outbound> ob);

    // Evaluate ACL for a given address. Returns the outbound to use.
    // Also fills hijackAddr if a hijack rule matched.
    std::shared_ptr<server::Outbound> Evaluate(
        const std::string& host, uint16_t port, AclProto proto,
        std::string* hijackAddr = nullptr);

    // Outbound interface - routes TCP/UDP through ACL
    std::shared_ptr<server::IConn> TCP(const std::string& reqAddr) override;
    std::shared_ptr<server::IUdpConn> UDP(const std::string& reqAddr) override;
    bool CheckUDP(const std::string& reqAddr) override;

private:
    // Parse a single ACL rule line
    bool parseRule(const std::string& line, AclRule& rule);

    // Parse address matcher
    bool parseAddress(const std::string& addr, AclAddressMatcher& matcher);

    // Parse proto/port filter
    bool parseProtoPort(const std::string& pp, AclProto& proto, AclPortRange& port);

    // Match an address against a matcher
    bool matchAddress(const AclAddressMatcher& matcher, const std::string& host);

    // Match port against port range
    bool matchPort(const AclPortRange& range, uint16_t port);

    // Split host:port from request address
    static bool splitHostPort(const std::string& addr, std::string& host, uint16_t& port);

    std::vector<AclRule> rules_;
    std::unordered_map<std::string, std::shared_ptr<server::Outbound>> outbounds_;
    std::shared_ptr<server::Outbound> defaultOutbound_;
};

} // namespace hy2::outbounds
