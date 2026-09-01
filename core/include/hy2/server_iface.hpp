// server_iface.hpp - Server-side interfaces, StreamStats and config structs.
// Rewrite of core/server/config.go (interfaces part).
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "hy2/atomic_utils.hpp"
#include "hy2/common.hpp"
#include "hy2/error.hpp"
#include "hy2/io.hpp"

namespace hy2::server {

// ---------------------------------------------------------------------------
// Basic connection abstractions

// IConn mirrors net.Conn (read/write/close) used for TCP proxying targets.
class IConn : public IByteReaderWriter {
public:
    void Close() override = 0;
};

// IUdpConn is like net.PacketConn, but uses strings for addresses
// (mirrors server.UDPConn).
//
// THREAD-SAFETY CONTRACT (mirrors Go's net.Conn guarantees, on which
// udpSessionEntry relies): implementations MUST make Close() safe to call
// concurrently with ReadFrom()/WriteTo() from other threads - a blocked
// ReadFrom must unblock (throw) after Close. Implementations must also be
// safe for concurrent WriteTo calls.
class IUdpConn {
public:
    virtual ~IUdpConn() = default;
    // ReadFrom blocks; throws on error/closed (Go returns err).
    virtual size_t ReadFrom(uint8_t* buf, size_t len, std::string& addr) = 0;
    virtual void WriteTo(const uint8_t* buf, size_t len, const std::string& addr) = 0;
    virtual void Close() = 0;
};

// ---------------------------------------------------------------------------
// HTTP abstractions (subset needed for auth + masquerading)

using HeaderMap = std::map<std::string, std::string>;

struct HttpRequest {
    std::string Method;
    std::string Host;
    std::string Path;
    HeaderMap Header;
};

class HttpResponseWriter {
public:
    virtual ~HttpResponseWriter() = default;
    virtual HeaderMap& Header() = 0;
    virtual void WriteHeader(int status) = 0;
    virtual void Write(const uint8_t* p, size_t n) = 0;
};

class IHttpHandler {
public:
    virtual ~IHttpHandler() = default;
    virtual void ServeHTTP(HttpResponseWriter& w, const HttpRequest& r) = 0;
};

// ---------------------------------------------------------------------------
// Extension interfaces (mirrors of the Go ones)

// Outbound provides the implementation of how the server should connect to
// remote servers.
class Outbound {
public:
    virtual ~Outbound() = default;
    virtual std::shared_ptr<IConn> TCP(const std::string& reqAddr) = 0;
    virtual std::shared_ptr<IUdpConn> UDP(const std::string& reqAddr) = 0;
    // CheckUDP: return true to permit, false to reject (nil error == allow).
    virtual bool CheckUDP(const std::string& reqAddr) = 0;
};

// Authenticator is an interface that provides authentication logic.
class Authenticator {
public:
    virtual ~Authenticator() = default;
    virtual bool Authenticate(const std::string& addr, const std::string& auth,
                              uint64_t tx, std::string& idOut) = 0;
};

// EventLogger is an interface that provides logging logic.
class EventLogger {
public:
    virtual ~EventLogger() = default;
    virtual void Connect(const std::string&, const std::string&, uint64_t) {}
    virtual void Disconnect(const std::string&, const std::string&, const std::string&) {}
    virtual void TCPRequest(const std::string&, const std::string&, const std::string&) {}
    virtual void TCPError(const std::string&, const std::string&, const std::string&,
                          const std::string&) {}
    virtual void UDPRequest(const std::string&, const std::string&, uint32_t,
                            const std::string&) {}
    virtual void UDPError(const std::string&, const std::string&, uint32_t, const std::string&) {}
};

enum class StreamState {
    // Initial indicates the initial state of a stream.
    // Client has opened the stream, but we have not received the proxy request yet.
    Initial = 0,
    // Hooking indicates that the hook (usually sniff) is processing.
    Hooking,
    // Connecting indicates that we are connecting to the proxy target.
    Connecting,
    // Established indicates the proxy is established.
    Established,
    // Closed indicates the stream is closed.
    Closed,
};

inline const char* StreamStateString(StreamState s) {
    switch (s) {
    case StreamState::Initial: return "init";
    case StreamState::Hooking: return "hook";
    case StreamState::Connecting: return "connect";
    case StreamState::Established: return "estab";
    case StreamState::Closed: return "closed";
    default: return "unknown";
    }
}

// TrafficLogger - Tx/Rx in this context refers to the server-remote
// (proxy target) perspective. LogTraffic returning false signals disconnect.
class StreamStats;

class ITrafficLogger {
public:
    virtual ~ITrafficLogger() = default;
    virtual bool LogTraffic(const std::string& id, uint64_t tx, uint64_t rx) = 0;
    virtual void LogOnlineState(const std::string& id, bool online) = 0;
    virtual void TraceStream(IHyStream*, StreamStats*) {}
    virtual void UntraceStream(IHyStream*) {}
};

// RequestHook allows filtering and modifying requests before the server
// connects to the remote. A request will only be hooked if Check returns true.
class IRequestHook {
public:
    virtual ~IRequestHook() = default;
    virtual bool Check(bool isUDP, const std::string& reqAddr) = 0;
    // TCP may modify reqAddr; returned bytes are "put back" to the remote.
    // Throws to abort the connection.
    virtual std::vector<uint8_t> TCP(IHyStream& stream, std::string& reqAddr) = 0;
    // UDP may modify reqAddr. Throws to abort.
    virtual void UDP(std::vector<uint8_t>& data, std::string& reqAddr) = 0;
};

// ---------------------------------------------------------------------------
// StreamStats

class StreamStats {
public:
    Atomic<StreamState> State{StreamState::Initial};
    std::string AuthID;
    uint32_t ConnID = 0;

    void SetInitialTimeNow() {
        LastActiveTime.Set(MonoTime::Now().ns);
    }

    Atomic<std::string> ReqAddr;
    Atomic<std::string> HookedReqAddr;

    std::atomic<uint64_t> Tx{0};
    std::atomic<uint64_t> Rx{0};

    AtomicTime LastActiveTime{};

    void setHookedReqAddr(const std::string& addr) {
        if (addr != ReqAddr.Load()) {
            HookedReqAddr.Store(addr);
        }
    }
};

} // namespace hy2::server
