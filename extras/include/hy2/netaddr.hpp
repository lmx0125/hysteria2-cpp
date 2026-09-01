// netaddr.hpp - Small network-address helpers mirroring Go's
// net.SplitHostPort / net.JoinHostPort / net.ParseIP for the extras packages.
// Literal IPs only (no DNS); IPv6 is parsed and formatted per RFC 5952,
// matching Go's canonical output.
#pragma once

#include <optional>
#include <string>
#include <utility>

namespace hy2 {

// SplitHostPort splits "host:port", "[v6]:port" etc. On failure returns
// nullopt and sets errOut to a Go net.AddrError-style message:
// "address <addr>: <why>" (or just "<why>" when the address is empty).
std::optional<std::pair<std::string, std::string>> SplitHostPort(
    const std::string& hostPort, std::string& errOut);

// Convenience overload for callers that ignore the error text.
inline std::optional<std::pair<std::string, std::string>> SplitHostPort(
    const std::string& hostPort) {
    std::string err;
    return SplitHostPort(hostPort, err);
}

// JoinHostPort mirrors Go net.JoinHostPort: brackets the host when it
// contains colons.
std::string JoinHostPort(const std::string& host, const std::string& port);

// IsIP reports whether s is a valid literal IPv4 or IPv6 address
// (mirror of Go net.ParseIP(s) != nil; zones and leading zeros rejected).
bool IsIP(const std::string& s);

// CanonicalizeIP returns the canonical textual form of a valid literal IP
// (IPv4 unchanged; IPv6 compressed per RFC 5952 like Go's IP.String()).
// Returns an empty string if s is not a valid literal IP.
std::string CanonicalizeIP(const std::string& s);

} // namespace hy2
