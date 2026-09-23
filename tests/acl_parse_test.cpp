// acl_parse_test.cpp - Tests for ACL rule-text parsing, specifically the
// dotted-decimal IPv4 parser.
//
// ParseIPv4Bytes used to be istringstream + getline + stoi and is now a
// hand-rolled scanner (no locale object, no per-token string, no stream). The
// acceptance rules must be identical: a string that used to be classified as
// an IPv4 address must still be, and one that was rejected must still fall
// through to the domain-rule path rather than silently becoming an IP rule.
#include "hytest.hpp"

#include "hy2/acl.hpp"

#include <cstdint>
#include <string>

using hy2::Acl;
using hy2::AclAction;
using hy2::AclRuleType;

namespace {

void Ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t out[4]) {
    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
}

Acl ParseOne(const std::string& ruleText) {
    return Acl::Parse(ruleText, AclAction::Deny);
}

} // namespace

// A CIDR rule must match inside its range and not outside it.
HY_TEST(AclParse_IPv4CidrMatchesRange)
{
    Acl acl = ParseOne("allow 192.168.1.0/24");
    HY_CHECK_EQ(acl.RuleCount(), static_cast<size_t>(1));

    uint8_t in[4], out[4];
    Ip4(192, 168, 1, 5, in);
    Ip4(192, 168, 2, 5, out);
    HY_CHECK(acl.EvaluateIp4(in, 80) == AclAction::Allow);
    HY_CHECK(acl.EvaluateIp4(out, 80) == AclAction::Deny);
}

// A bare IP literal rule must match exactly that address.
HY_TEST(AclParse_IPv4LiteralMatchesExactly)
{
    Acl acl = ParseOne("allow 10.1.2.3");

    uint8_t same[4], other[4];
    Ip4(10, 1, 2, 3, same);
    Ip4(10, 1, 2, 4, other);
    HY_CHECK(acl.EvaluateIp4(same, 80) == AclAction::Allow);
    HY_CHECK(acl.EvaluateIp4(other, 80) == AclAction::Deny);
}

// Leading zeros were accepted by the old parser (stoi skips them); keep that.
HY_TEST(AclParse_IPv4LeadingZerosAccepted)
{
    Acl acl = ParseOne("allow 010.000.000.001");

    uint8_t want[4], other[4];
    Ip4(10, 0, 0, 1, want);
    Ip4(10, 0, 0, 2, other);
    HY_CHECK(acl.EvaluateIp4(want, 80) == AclAction::Allow);
    HY_CHECK(acl.EvaluateIp4(other, 80) == AclAction::Deny);
}

// Boundary octets.
HY_TEST(AclParse_IPv4Boundaries)
{
    Acl zero = ParseOne("allow 0.0.0.0");
    uint8_t z[4];
    Ip4(0, 0, 0, 0, z);
    HY_CHECK(zero.EvaluateIp4(z, 80) == AclAction::Allow);

    Acl max = ParseOne("allow 255.255.255.255");
    uint8_t m[4];
    Ip4(255, 255, 255, 255, m);
    HY_CHECK(max.EvaluateIp4(m, 80) == AclAction::Allow);
}

// An out-of-range octet must not be accepted as an IPv4 address. It falls
// through to the domain path, so it matches a host name containing that text
// but no IP at all.
HY_TEST(AclParse_IPv4OutOfRangeIsNotAnIpRule)
{
    Acl acl = ParseOne("allow 256.1.1.1");
    HY_CHECK_EQ(acl.RuleCount(), static_cast<size_t>(1));

    uint8_t ip[4];
    Ip4(56, 1, 1, 1, ip);
    HY_CHECK(acl.EvaluateIp4(ip, 80) == AclAction::Deny);

    // ...and it is a keyword domain rule, which is the documented fallback.
    HY_CHECK(acl.Evaluate("x256.1.1.1y", 80) == AclAction::Allow);
}

// Too few components must not be accepted as IPv4 either.
HY_TEST(AclParse_IPv4TooFewComponentsFallsBackToDomain)
{
    Acl acl = ParseOne("allow 1.2.3");
    uint8_t ip[4];
    Ip4(1, 2, 3, 4, ip);
    HY_CHECK(acl.EvaluateIp4(ip, 80) == AclAction::Deny);
    HY_CHECK(acl.Evaluate("1.2.3", 80) == AclAction::Allow); // keyword match
}

// A trailing dot leaves an empty component, which is invalid.
HY_TEST(AclParse_IPv4TrailingDotIsNotAnIpRule)
{
    Acl acl = ParseOne("allow 1.2.3.");
    uint8_t ip[4];
    Ip4(1, 2, 3, 4, ip);
    HY_CHECK(acl.EvaluateIp4(ip, 80) == AclAction::Deny);
}

// Non-digit characters must be rejected rather than parsed leniently.
HY_TEST(AclParse_IPv4NonDigitsRejected)
{
    for (const char* text : {"allow 1.2.3.x", "allow 1.2.3.4x", "allow 1.2.-3.4",
                             "allow 1.2.3.4.5.6.7"}) {
        Acl acl = ParseOne(text);
        uint8_t ip[4];
        Ip4(1, 2, 3, 4, ip);
        // "1.2.3.4.5.6.7" is accepted by both old and new parsers as 1.2.3.4
        // (the scanner stops after four components); the rest must not match.
        if (std::string(text).find(".5.6.7") != std::string::npos) continue;
        HY_CHECK(acl.EvaluateIp4(ip, 80) == AclAction::Deny);
    }
}