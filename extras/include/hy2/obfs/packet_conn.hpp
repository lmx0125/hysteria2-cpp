// packet_conn.hpp - Minimal net.PacketConn (UDP-flavor) analog for extras.
// Addresses are opaque strings ("host:port"); errors are reported by
// throwing hy2::Error subclasses.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace hy2::obfs {

class IPacketConn {
public:
    virtual ~IPacketConn() = default;

    // Blocks until a datagram arrives; copies up to len bytes into buf and
    // returns the datagram length. Throws when closed or on error.
    virtual size_t ReadFrom(uint8_t* buf, size_t len, std::string& addr) = 0;

    // Sends one datagram to addr. Throws on error; returns original length
    // implicitly by not throwing (void mirrors Go's n==len(p), err==nil).
    virtual void WriteTo(const uint8_t* data, size_t len, const std::string& addr) = 0;

    virtual void Close() = 0;
    virtual std::string LocalAddr() const = 0;
};

} // namespace hy2::obfs
