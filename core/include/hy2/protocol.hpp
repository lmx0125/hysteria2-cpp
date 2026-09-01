// protocol.hpp - Wire protocol framing. Direct C++ rewrite of
// hysteria/core/v2/internal/protocol (proxy.go, padding.go, http.go).
//
// All multibyte numbers are Big Endian; varints follow QUIC RFC 9000.
#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>

#include "common.hpp"
#include "io.hpp"

namespace hy2::proto {

constexpr uint64_t FrameTypeTCPRequest = 0x401;

// Max length values are for preventing DoS attacks
constexpr size_t kMaxAddressLength = 2048;
constexpr size_t kMaxMessageLength = 2048;
constexpr size_t kMaxPaddingLength = 4096;

constexpr ByteCount kMaxDatagramFrameSize = 1200;
constexpr size_t kMaxUDPSize = 4096;

const std::string URLHost = "hysteria";
const std::string URLPath = "/auth";

const char RequestHeaderAuth[] = "Hysteria-Auth";
const char ResponseHeaderUDPEnabled[] = "Hysteria-UDP";
const char CommonHeaderCCRX[] = "Hysteria-CC-RX";
const char CommonHeaderPadding[] = "Hysteria-Padding";

constexpr int StatusAuthOK = 233;

using HeaderMap = std::map<std::string, std::string>;

// ---------------------------------------------------------------------------
// Padding (padding.go)

// padding specifies a half-open range [Min, Max).
struct Padding {
    int Min = 0;
    int Max = 0;
    // String generates a random string of random length [Min, Max),
    // consisting of [a-zA-Z0-9]. Mirrors padding.String().
    std::string String() const;
};

Padding AuthRequestPadding();
Padding AuthResponsePadding();
Padding TCPRequestPadding();
Padding TCPResponsePadding();

// ---------------------------------------------------------------------------
// TCPRequest / TCPResponse (proxy.go)
//
// TCPRequest format:
//   0x401 (QUIC varint)
//   Address length (QUIC varint)
//   Address (bytes)
//   Padding length (QUIC varint)
//   Padding (bytes)

// ReadTCPRequest reads a TCP request from r and returns the address.
// r must start at the address length (frame type already consumed).
std::string ReadTCPRequest(IByteReader& r);

// WriteTCPRequest writes a TCP request with generated padding to w.
void WriteTCPRequest(IByteWriter& w, const std::string& addr);

// SerializeTCPRequest builds the full request bytes (for tests/tools).
std::vector<uint8_t> SerializeTCPRequest(const std::string& addr);

// TCPResponse format:
//   Status (byte, 0=ok, 1=error)
//   Message length (QUIC varint)
//   Message (bytes)
//   Padding length (QUIC varint)
//   Padding (bytes)

struct TCPResponseResult {
    bool OK = false;
    std::string Message;
};

TCPResponseResult ReadTCPResponse(IByteReader& r);
void WriteTCPResponse(IByteWriter& w, bool ok, const std::string& msg);
std::vector<uint8_t> SerializeTCPResponse(bool ok, const std::string& msg);

// ---------------------------------------------------------------------------
// UDPMessage (proxy.go)
//
// UDPMessage format:
//   Session ID (uint32 BE)
//   Packet ID (uint16 BE)
//   Fragment ID (uint8)
//   Fragment count (uint8)
//   Address length (QUIC varint)
//   Address (bytes)
//   Data...

struct UDPMessage {
    uint32_t SessionID = 0; // 4
    uint16_t PacketID = 0;  // 2
    uint8_t FragID = 0;     // 1
    uint8_t FragCount = 0;  // 1
    std::string Addr;       // varint + bytes
    std::vector<uint8_t> Data;

    size_t HeaderSize() const;
    size_t Size() const { return HeaderSize() + Data.size(); }

    // Serialize writes the message to buf. Returns the number of bytes written,
    // or -1 if the buffer is too small. Mirrors (*UDPMessage).Serialize.
    int Serialize(uint8_t* buf, size_t bufLen) const;
};

// ParseUDPMessage parses a UDPMessage from msg. Throws ProtocolError on
// invalid input (mirrors ParseUDPMessage).
UDPMessage ParseUDPMessage(const uint8_t* msg, size_t len);
inline UDPMessage ParseUDPMessage(const std::vector<uint8_t>& v) {
    return ParseUDPMessage(v.data(), v.size());
}

// ParseUDPMessageInPlace parses into an existing UDPMessage, reusing its
// Addr string and Data vector buffers to avoid heap allocation on repeated calls.
// The previous contents of m are overwritten.
void ParseUDPMessageInPlace(UDPMessage& m, const uint8_t* msg, size_t len);

// ---------------------------------------------------------------------------
// HTTP auth headers (http.go)

struct AuthRequest {
    std::string Auth;
    uint64_t Rx = 0; // 0 = unknown, client asks server to use bandwidth detection
};

struct AuthResponse {
    bool UDPEnabled = false;
    uint64_t Rx = 0;     // 0 = unlimited
    bool RxAuto = false; // true = server asks client to use bandwidth detection
};

AuthRequest AuthRequestFromHeader(const HeaderMap& h);
void AuthRequestToHeader(HeaderMap& h, const AuthRequest& req);

AuthResponse AuthResponseFromHeader(const HeaderMap& h);
void AuthResponseToHeader(HeaderMap& h, const AuthResponse& resp);

} // namespace hy2::proto
