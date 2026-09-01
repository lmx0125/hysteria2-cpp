#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "hy2/client.hpp"
#include "hy2/quic.hpp"

namespace hy2::quic_backend {

// ---------------------------------------------------------------------------
// H3AuthRoundTripper: implements ClientTransport using a real QUIC connection
// and minimal HTTP/3 framing for the /auth POST request.
//
// This replaces the Go code's http3.RoundTripper for the auth handshake.
// The HTTP/3 framing is intentionally minimal: we only need to send one
// POST request and receive one response — not full H3.
//
// HTTP/3 frame layout (RFC 9114):
//   HEADERS frame (type=0x01): encodes :method, :path, :scheme, :authority, auth headers
//   DATA frame (type=0x00): optional body
//   SETTINGS frame (type=0x04): must be first on control stream
// ---------------------------------------------------------------------------
class H3AuthRoundTripper : public client::ClientTransport {
public:
    struct Params {
        std::string serverAddr;    // "host:port"
        std::string serverName;    // SNI
        bool insecureSkipVerify = false;
        std::vector<std::string> rootCAsPEM;
    };

    explicit H3AuthRoundTripper(Params params);
    ~H3AuthRoundTripper() override;

    AuthResult RoundTrip(const client::Config& cfg, const proto::AuthRequest& req) override;

private:
    // Build the HEADERS frame encoding for the auth request.
    std::vector<uint8_t> BuildAuthHeaders(const client::Config& cfg,
                                          const proto::AuthRequest& req) const;

    // Build a minimal SETTINGS frame.
    std::vector<uint8_t> BuildSettingsFrame() const;

    // Parse HTTP/3 response headers from a HEADERS frame.
    proto::HeaderMap ParseResponseHeaders(const uint8_t* data, size_t len) const;

    // Extract the :status pseudo-header from parsed headers.
    int GetStatusCode(const proto::HeaderMap& headers) const;

    Params params_;
};

} // namespace hy2::quic_backend
