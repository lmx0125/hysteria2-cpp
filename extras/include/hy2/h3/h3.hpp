// h3.hpp - Minimal HTTP/3 (RFC 9114) layer for the Hysteria2 auth exchange
// and enough plumbing for request/response over a real QUIC connection.
//
// Scope: unidirectional control stream with SETTINGS, HEADERS/DATA frames,
// one-request-per-bidi-stream. No QPACK dynamic table, no push, no GOAWAY
// handling beyond ignoring unknown frame types (required by RFC).
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "hy2/h3/qpack.hpp"
#include "hy2/quic.hpp"

namespace hy2::h3 {

// ---------------------------------------------------------------------------
// Frame types (RFC 9114 §7.2)
constexpr uint64_t FrameData = 0x0;
constexpr uint64_t FrameHeaders = 0x1;
constexpr uint64_t FrameCancelPush = 0x3;
constexpr uint64_t FrameSettings = 0x4;
constexpr uint64_t FrameGoaway = 0x7;

// Settings identifiers
constexpr uint64_t SettingQpackMaxTableCapacity = 0x1;
constexpr uint64_t SettingMaxFieldSectionSize = 0x6;
constexpr uint64_t SettingQpackBlockedStreams = 0x7;

// Uni stream types (§6.2)
constexpr uint64_t StreamTypeControl = 0x00;
constexpr uint64_t StreamTypePush = 0x01;
constexpr uint64_t StreamTypeQpackEncoder = 0x02;
constexpr uint64_t StreamTypeQpackDecoder = 0x03;

// ---------------------------------------------------------------------------
// Varint helpers (QUIC varints, shared with the rest of hy2)
void WriteVarint(std::vector<uint8_t>& out, uint64_t v);

struct FrameHeader {
    uint64_t type;
    std::vector<uint8_t> payload; // whole payload (small frames only)
};

// Reads one frame from a QUIC stream. Blocking. Throws on EOF/error.
FrameHeader ReadFrame(IQuicStream& s);

// Writes type+length; caller appends payload via the same stream.
std::vector<uint8_t> EncodeFrameHeader(uint64_t type, size_t payloadLen);

// SETTINGS body advertising zero-capacity QPACK (forces static-only peers).
std::vector<uint8_t> BuildClientSettingsBody();
std::vector<uint8_t> BuildServerSettingsBody();

// Opens a control stream on `conn` and writes the stream-type + SETTINGS.
void SendControlStream(IQuicConnection& conn,
                       const std::vector<uint8_t>& settingsBody);

// ---------------------------------------------------------------------------
// Client-side request/response
struct Response {
    int StatusCode = 0;
    std::vector<Header> Headers;
    std::vector<uint8_t> Body;
};

// Sends POST {scheme}://{host}{path} with headers (no body) and reads the
// full response. Blocks until the response stream ends.
Response Request(IQuicConnection& conn,
                 const std::string& method,
                 const std::string& schemeAndHost,
                 const std::string& path,
                 const std::vector<Header>& extraHeaders,
                 const std::vector<uint8_t>* body = nullptr);

// ---------------------------------------------------------------------------
// Server-side single request stream handler
struct ServerRequest {
    std::string Method;
    std::string Scheme;
    std::string Authority;
    std::string Path;
    std::vector<Header> Headers;
    std::vector<uint8_t> Body;
};

// Parses one request from a bidi stream (HEADERS [+ DATA] until FIN).
ServerRequest ReadRequest(IQuicStream& s);

// Writes a response: HEADERS with :status plus headers, then FIN.
void SendResponse(IQuicStream& s, int status,
                  const std::vector<Header>& headers,
                  const std::vector<uint8_t>* body = nullptr);

} // namespace hy2::h3
