// error.hpp - Error types mirroring hysteria/core/v2/errors (Go).
// All errors are thrown as exceptions; what() strings match the Go
// Error() implementations exactly for seamless log/message migration.
#pragma once

#include <stdexcept>
#include <string>

#include "common.hpp"

namespace hy2 {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string& msg) : std::runtime_error(msg) {}
};

// ConfigError is returned when a configuration field is invalid.
// Go: "invalid config: %s: %s"
class ConfigError : public Error {
public:
    std::string Field;
    std::string Reason;
    ConfigError(std::string field, std::string reason)
        : Error("invalid config: " + field + ": " + reason),
          Field(std::move(field)), Reason(std::move(reason)) {}
};

// ConnectError is returned when the client fails to connect to the server.
// Go: "connect error: " + err
class ConnectError : public Error {
public:
    std::string Inner;
    explicit ConnectError(std::string inner)
        : Error("connect error: " + inner), Inner(std::move(inner)) {}
};

// AuthError is returned when the client fails to authenticate with the server.
// Go: "authentication error, HTTP status code: %d"
class AuthError : public Error {
public:
    int StatusCode = 0;
    explicit AuthError(int statusCode)
        : Error("authentication error, HTTP status code: " + std::to_string(statusCode)),
          StatusCode(statusCode) {}
};

// DialError is returned when the server rejects the client's dial request.
// Go: "dial error: " + msg
class DialError : public Error {
public:
    std::string Message;
    explicit DialError(std::string message)
        : Error("dial error: " + message), Message(std::move(message)) {}
};

// ClosedError is returned when the client attempts to use a closed connection.
// Go: "connection closed" / "connection closed: <err>"
class ClosedError : public Error {
public:
    std::string Inner; // may be empty (nil in Go)
    explicit ClosedError(std::string inner = "")
        : Error(inner.empty() ? "connection closed" : "connection closed: " + inner),
          Inner(std::move(inner)) {}
};

// ProtocolError is returned on unexpected/malformed requests/responses/messages.
// Go: "protocol error: " + msg
class ProtocolError : public Error {
public:
    std::string Message;
    explicit ProtocolError(std::string message)
        : Error("protocol error: " + message), Message(std::move(message)) {}
};

// ---------------------------------------------------------------------------
// Transport-level errors that mirror specific quic-go error types which the
// session logic inspects.

// DatagramTooLargeError mirrors quic.ErrDatagramTooLarge. The session code
// uses MaxDatagramPayloadSize to decide the fragmentation size.
class DatagramTooLargeError : public Error {
public:
    ByteCount MaxDatagramPayloadSize = 0;
    explicit DatagramTooLargeError(int64_t maxDatagramPayloadSize)
        : Error("datagram too large"), MaxDatagramPayloadSize(maxDatagramPayloadSize) {}
};

// StreamLimitReachedError mirrors quic.StreamLimitReachedError - a
// non-permanent error that must not be wrapped as ClosedError.
class StreamLimitReachedError : public Error {
public:
    StreamLimitReachedError() : Error("stream limit reached") {}
};

// TrafficLogger requested disconnect (Go: var errDisconnect).
class ErrDisconnect : public Error {
public:
    ErrDisconnect() : Error("traffic logger requested disconnect") {}
};

} // namespace hy2
