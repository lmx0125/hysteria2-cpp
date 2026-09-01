// sniff.hpp - Rewrite of extras/sniff/sniff.go (TCP HTTP/TLS sniffing).
// The QUIC/UDP path needs full QUIC Initial decryption (HKDF + AEAD) and is
// not implemented; UDP() mirrors the Go "unrecognized protocol" no-op.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "hy2/common.hpp"
#include "hy2/io.hpp"
#include "hy2/netaddr.hpp"
#include "hy2/portunion.hpp"
#include "hy2/server_iface.hpp"

namespace hy2::sniff {

// Go: sniffDefaultTimeout / sniffMaxHTTPHeaderBytes
constexpr Duration kSniffDefaultTimeout = Duration::FromSeconds(4);
constexpr size_t kSniffMaxHTTPHeaderBytes = 256 * 1024;

// Sniffer is a server core RequestHook that performs packet inspection and
// possibly rewrites the request address based on what's in the protocol
// header. This is mainly for inbounds that inherently cannot get domain
// information (e.g. TUN), in which case sniffing can restore the domains and
// apply ACLs correctly. Currently supports HTTP and HTTPS (TLS) over TCP.
class Sniffer : public server::IRequestHook {
public:
    Duration Timeout{}; // zero => kSniffDefaultTimeout
    bool RewriteDomain = false; // Whether to rewrite the address even when it's already a domain
    PortUnion TCPPorts;         // empty => all ports (mirrors Go nil)
    PortUnion UDPPorts;         // empty => all ports

    bool Check(bool isUDP, const std::string& reqAddr) override;
    // TCP reads some initial bytes from the stream, possibly rewrites
    // reqAddr and returns the bytes to put back. Throws hy2::Error when Go
    // returns an error.
    std::vector<uint8_t> TCP(IHyStream& stream, std::string& reqAddr) override;
    // Not implemented (requires decrypting the QUIC Initial packet); behaves
    // like Go's "unrecognized protocol" path: leaves everything untouched.
    void UDP(std::vector<uint8_t>& data, std::string& reqAddr) override;

private:
    static bool isHTTP(const uint8_t* buf, size_t len);
    static bool isTLS(const uint8_t* buf, size_t len);
};

// Parses a TLS ClientHello handshake message (strict, mirroring
// utls.UnmarshalClientHello) and returns the SNI hostname, if present.
// Trailing dot trimmed like crypto/tls.
std::optional<std::string> UnmarshalClientHelloSNI(const uint8_t* data, size_t len);

} // namespace hy2::sniff
