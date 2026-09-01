// server_udp.hpp - Server UDP session manager. Rewrite of core/server/udp.go.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>

#include "hy2/frag.hpp"
#include "hy2/protocol.hpp"
#include "hy2/quic.hpp"
#include "hy2/server_iface.hpp"

namespace hy2::server {

constexpr int64_t kIdleCleanupIntervalNs = Duration::FromSeconds(1).ns;
constexpr size_t kMaxSessionACLCache = 256;

// UdpIO mirrors the udpIO interface in udp.go.
class UdpIO {
public:
    virtual ~UdpIO() = default;
    // ReceiveMessage blocks; throws on connection error (stops the manager).
    virtual std::shared_ptr<proto::UDPMessage> ReceiveMessage() = 0;
    // SendMessage serializes msg into buf and sends. May throw
    // DatagramTooLargeError (caller decides on fragmentation).
    virtual void SendMessage(uint8_t* buf, size_t bufLen, const proto::UDPMessage& msg) = 0;
    // Hook may modify reqAddr; throws to abort the session dial.
    virtual void Hook(std::vector<uint8_t>& data, std::string& reqAddr) = 0;
    virtual std::shared_ptr<IUdpConn> UDP(const std::string& reqAddr) = 0;
    virtual bool CheckUDP(const std::string& reqAddr) = 0; // true == allow
};

class UdpEventLogger {
public:
    virtual ~UdpEventLogger() = default;
    virtual void New(uint32_t sessionID, const std::string& reqAddr) = 0;
    virtual void Close(uint32_t sessionID, const std::string& err) = 0;
};

// UdpSessionEntry - one NAT-like UDP session (port of udpSessionEntry).
class UdpSessionEntry : public std::enable_shared_from_this<UdpSessionEntry> {
public:
    uint32_t ID = 0;
    std::string OverrideAddr; // Ignore the address in the UDP message, always use this if not empty
    std::string OriginalAddr; // The original address in the UDP message
    frag::Defragger D;
    AtomicTime Last;
    UdpIO* IO = nullptr;

    using DialFuncT = std::function<std::shared_ptr<IUdpConn>(const std::string& addr,
                                                              const std::vector<uint8_t>& firstMsgData,
                                                              std::string& actualAddr)>;
    using ExitFuncT = std::function<void(const std::string& err)>;

    DialFuncT DialFunc;
    ExitFuncT ExitFunc;

    // ioKeep optionally retains a shared owner of *IO so the entry's receive
    // loop can never touch a freed UdpIO even if its creator dies first.
    UdpSessionEntry(uint32_t id, UdpIO* io, DialFuncT dialFunc, ExitFuncT exitFunc,
                    std::shared_ptr<UdpIO> ioKeep = nullptr);

    ~UdpSessionEntry();

    // CloseWithErr closes the session and calls ExitFunc with the given error.
    // An empty error indicates cleanup due to timeout.
    void CloseWithErr(const std::string& err);

    // Feed feeds a UDP message to the session. Returns bytes written to the
    // session's UDP connection when a complete message is available, else 0.
    // Throws on send/dial errors (mirrors returned error in Go).
    size_t Feed(std::shared_ptr<const proto::UDPMessage> msg);

    // Joins the receive-loop thread (blocks until it exits). Used by
    // UdpSessionManager::Stop for deterministic shutdown; safe because the
    // loop exits once the connection is closed (see IUdpConn contract).
    void JoinReceiveLoopForShutdown();

private:
    void receiveLoop();
    bool checkAddr(const std::string& addr);
    void initConnLocked(const proto::UDPMessage& firstMsg); // caller holds connMutex_

    std::shared_ptr<IUdpConn> conn_;
    std::recursive_mutex connMutex_;
    bool closed_ = false;
    std::mutex aclMutex_;
    std::map<std::string, bool> aclCache_;
    std::atomic<bool> receiveLoopStarted_{false};
    // Owned receive thread: joined by JoinReceiveLoopForShutdown() or the
    // destructor - UNLESS the destructor runs on the receive thread itself
    // (possible when the thread's own self-reference was the last owner),
    // in which case the thread detaches instead of deadlocking on join().
    std::thread receiveThread_;
    std::thread::id receiveThreadId_;
    std::shared_ptr<UdpIO> ioKeep_;
};

// sendMessageAutoFrag: tries whole-message send, fragments with a random
// packet ID upon DatagramTooLargeError. Returns nothing; throws on failure.
void SendMessageAutoFrag(UdpIO& io, uint8_t* buf, size_t bufLen, proto::UDPMessage& msg);

// UdpSessionManager manages the lifecycle of UDP sessions (NAT).
//
// Lifetime: use the static Create() factory when a background run thread is
// desired - it starts Run() on a detached thread holding shared ownership of
// the manager, so the manager outlives external handles exactly as long as
// the receive loop needs it (mirroring Go where sm.Run() holds *udpSession-
// Manager). The manager also keeps its io/eventLogger alive via keepalive
// pointers passed to Create().
class UdpSessionManager : public std::enable_shared_from_this<UdpSessionManager> {
public:
    // Direct construction: no threads started. Run() must be called manually
    // (tests use this with feed()/Stop() only).
    UdpSessionManager(UdpIO* io, UdpEventLogger* eventLogger, Duration idleTimeout);

    // Factory for background operation: constructs the manager and launches
    // Run() on a detached thread that shares ownership. The io and logger are
    // retained (kept alive) by the manager.
    static std::shared_ptr<UdpSessionManager> Create(std::shared_ptr<UdpIO> io,
                                                     std::shared_ptr<UdpEventLogger> eventLogger,
                                                     Duration idleTimeout);

    ~UdpSessionManager();

    // Run runs the main loop until the underlying io throws (connection
    // closed). Also runs the idle-cleanup ticker; on exit all sessions are
    // cleaned up and the cleaner thread is joined.
    void Run();

    // Stop stops the idle cleanup ticker and cleans up all sessions.
    // Safe to call even if Run() was never invoked.
    void Stop();

    // Feed delivers a message into the session map (public for tests,
    // mirroring Go in-package test access).
    void feed(std::shared_ptr<proto::UDPMessage> msg);

    size_t Count();

    // Session dial/exit logic used by entry callbacks. Public so the
    // capture-minimal lambdas in feed() can dispatch through either a locked
    // shared_ptr (managed mode) or a raw pointer (test/direct mode).
    std::shared_ptr<IUdpConn> DialFor(uint32_t sid, const std::string& addr,
                                      const std::vector<uint8_t>& firstMsgData,
                                      std::string& actualAddr);
    void ExitFor(uint32_t sid, const std::string& err);

    bool IsStopped() const { return stopFlag_.load(std::memory_order_acquire); }

private:
    void idleCleanupLoop();
    void cleanup(bool idleOnly);

    UdpIO* io_;
    UdpEventLogger* eventLogger_;
    Duration idleTimeout_;

    // Keepalives used by Create(); empty for direct construction.
    std::shared_ptr<UdpIO> ioKeep_;
    std::shared_ptr<UdpEventLogger> eventLoggerKeep_;

    std::shared_mutex mutex_;
    std::map<uint32_t, std::shared_ptr<UdpSessionEntry>> m_;

    // Live-session registry: lets Stop() deterministically join every
    // receive-loop thread before the manager's members are destroyed.
    std::mutex registryMutex_;
    std::vector<std::shared_ptr<UdpSessionEntry>> liveEntries_;

    std::mutex ctlMutex_; // guards cleanerThread_ lifecycle + stopFlag_
    std::thread cleanerThread_;
    std::atomic<bool> stopFlag_{false};
};

} // namespace hy2::server
