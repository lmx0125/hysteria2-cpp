// proxymux.hpp - Protocol multiplexer: routes connections to SOCKS5 or HTTP proxy.
// Rewrite of app/internal/proxymux/mux.go + manager.go.
// Cross-platform: no platform-specific code.
#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include "hy2/server_iface.hpp"

namespace hy2::proxy::proxymux {

// OpErr represents an operation error with protocol context.
struct OpErr {
    std::string Addr;
    std::string Protocol;
    std::string Op;
    std::string Err;
    std::string Error() const {
        return "mux-listen: " + Addr + "[" + Protocol + "]: " + Op + ": " + Err;
    }
};

// SubListener wraps a connection channel for a specific protocol (SOCKS or HTTP).
class SubListener {
public:
    // Accept returns the next connection for this protocol.
    // Blocks until a connection is available or the listener is closed.
    std::shared_ptr<server::IConn> Accept();

    // Close stops this sub-listener.
    void Close();

    bool IsClosed() const;

private:
    friend class MuxListener;

    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<server::IConn>> queue_;
    std::condition_variable cv_;
    bool closed_ = false;
};

// MuxListener multiplexes a single TCP listener into SOCKS5 and HTTP sub-listeners.
// Protocol detection: first byte 0x05 → SOCKS5, anything else → HTTP.
class MuxListener {
public:
    ~MuxListener();

    // ListenSOCKS returns a sub-listener for SOCKS5 connections.
    std::shared_ptr<SubListener> ListenSOCKS();

    // ListenHTTP returns a sub-listener for HTTP connections.
    std::shared_ptr<SubListener> ListenHTTP();

    // Close stops the multiplexer and all sub-listeners.
    void Close();

private:
    friend class MuxManager;

    explicit MuxListener(std::shared_ptr<server::IConn> base);

    void acceptLoop();
    void dispatch(std::shared_ptr<server::IConn> conn);

    std::shared_ptr<server::IConn> base_;
    std::thread acceptThread_;
    std::atomic<bool> closed_{false};

    std::mutex mutex_;
    std::shared_ptr<SubListener> socksListener_;
    std::shared_ptr<SubListener> httpListener_;
};

// MuxManager manages MuxListeners across different addresses.
class MuxManager {
public:
    static MuxManager& Instance();

    // GetOrCreate returns (or creates) a MuxListener for the given address.
    std::shared_ptr<MuxListener> GetOrCreate(const std::string& address);

    // ListenHTTP is a convenience method to get an HTTP listener on address.
    std::shared_ptr<SubListener> ListenHTTP(const std::string& address);

    // ListenSOCKS is a convenience method to get a SOCKS5 listener on address.
    std::shared_ptr<SubListener> ListenSOCKS(const std::string& address);

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<MuxListener>> listeners_;
};

} // namespace hy2::proxy::proxymux
