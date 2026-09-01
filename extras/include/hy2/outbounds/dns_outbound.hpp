// dns_outbound.hpp - DNS resolver for outbound ACL routing.
// Rewrite of extras/outbounds/dns_standard.go + dns_system.go + dns_https.go.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace hy2::outbounds {

// DnsResult contains the result of a DNS resolution.
struct DnsResult {
    std::string ipv4;
    std::string ipv6;
    bool hasIpv4 = false;
    bool hasIpv6 = false;
    std::string error;
};

// DnsResolver resolves hostnames to IP addresses.
class DnsResolver {
public:
    virtual ~DnsResolver() = default;
    virtual DnsResult Resolve(const std::string& hostname) = 0;
};

// SystemDnsResolver uses the OS DNS resolver (getaddrinfo).
class SystemDnsResolver : public DnsResolver {
public:
    DnsResult Resolve(const std::string& hostname) override;
};

// StandardDnsResolver uses UDP/TCP DNS queries (RFC 1035).
class StandardDnsResolver : public DnsResolver {
public:
    StandardDnsResolver(const std::string& serverAddr = "8.8.8.8:53",
                        bool useTcp = false);
    DnsResult Resolve(const std::string& hostname) override;

private:
    std::string serverAddr_;
    bool useTcp_;
};

// DohDnsResolver uses DNS over HTTPS (RFC 8484).
// Supports standard DoH servers like Cloudflare (1.1.1.1) and Google (8.8.8.8).
class DohDnsResolver : public DnsResolver {
public:
    // dohUrl: full DoH endpoint URL (e.g., "https://1.1.1.1/dns-query")
    //         or just server address (e.g., "1.1.1.1" or "https://8.8.8.8")
    // sni:    Server Name Indication for TLS (empty = use URL hostname)
    // insecure: skip TLS certificate verification
    DohDnsResolver(const std::string& dohUrl,
                   const std::string& sni = "",
                   bool insecure = false);
    DnsResult Resolve(const std::string& hostname) override;

private:
    std::string dohUrl_;
    std::string sni_;
    bool insecure_;

    // Build DNS wire format query for A and AAAA records
    std::vector<uint8_t> buildQuery(const std::string& hostname);
    // Parse DNS wire format response
    DnsResult parseResponse(const std::vector<uint8_t>& response);
};

} // namespace hy2::outbounds
