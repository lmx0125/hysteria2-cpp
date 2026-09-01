// server_udp.cpp - rewrite of core/server/udp.go
#include "hy2/server_udp.hpp"

#include <thread>

#include "hy2/common.hpp"
#include "hy2/error.hpp"

namespace hy2::server {

// ---------------------------------------------------------------------------
// UdpSessionEntry

UdpSessionEntry::UdpSessionEntry(uint32_t id, UdpIO* io, DialFuncT dialFunc,
                                 ExitFuncT exitFunc, std::shared_ptr<UdpIO> ioKeep)
    : ID(id), Last(AtomicTime(MonoTime::Now().ns)), IO(io),
      DialFunc(std::move(dialFunc)), ExitFunc(std::move(exitFunc)),
      ioKeep_(std::move(ioKeep)) {}

UdpSessionEntry::~UdpSessionEntry() {
    if (receiveThread_.joinable()) {
        if (receiveThreadId_ == std::this_thread::get_id()) {
            // The receive loop's own self-reference was the last owner, so
            // this destructor runs ON the receive thread. Joining ourselves
            // would throw resource_deadlock_would_occur (and escape as
            // std::terminate); the thread is about to finish anyway - detach.
            receiveThread_.detach();
        } else {
            receiveThread_.join();
        }
    }
}

void UdpSessionEntry::JoinReceiveLoopForShutdown() {
    if (receiveThread_.joinable() && receiveThreadId_ != std::this_thread::get_id()) {
        receiveThread_.join();
    }
}

void UdpSessionEntry::CloseWithErr(const std::string& err) {
    // We need this lock to ensure not to create conn after session exit
    std::lock_guard<std::recursive_mutex> lk(connMutex_);

    if (closed_) {
        // Already closed
        return;
    }

    closed_ = true;
    if (conn_) {
        try {
            conn_->Close();
        } catch (...) {
        }
    }

    ExitFunc(err);
}

size_t UdpSessionEntry::Feed(std::shared_ptr<const proto::UDPMessage> msg) {
    Last.Set(MonoTime::Now().ns);
    auto dfMsg = D.Feed(*msg);
    if (!dfMsg) {
        return 0;
    }

    {
        std::lock_guard<std::recursive_mutex> lk(connMutex_);
        if (!conn_) {
            initConnLocked(*dfMsg);
            if (OverrideAddr.empty()) {
                std::lock_guard<std::mutex> acl(aclMutex_);
                aclCache_.clear();
                aclCache_[dfMsg->Addr] = true; // first address is allowed
            }
        }
    }

    std::string addr = dfMsg->Addr;
    if (!OverrideAddr.empty()) {
        addr = OverrideAddr;
    } else if (!checkAddr(addr)) {
        throw Error("blocked");
    }

    size_t n = 0;
    conn_->WriteTo(dfMsg->Data.data(), dfMsg->Data.size(), addr);
    n = dfMsg->Data.size();
    return n;
}

bool UdpSessionEntry::checkAddr(const std::string& addr) {
    std::lock_guard<std::mutex> lk(aclMutex_);
    auto it = aclCache_.find(addr);
    if (it != aclCache_.end()) {
        return it->second;
    }
    bool decision = IO->CheckUDP(addr);
    if (aclCache_.size() >= kMaxSessionACLCache) {
        // Evict a random entry - mirrors Go, where map iteration order is
        // randomized so `for k := range m { delete(m, k); break }` removes an
        // arbitrary key. Keeps hit rates comparable to the Go build.
        auto victim = aclCache_.begin();
        std::advance(victim, static_cast<long>(RandomUint64() % aclCache_.size()));
        aclCache_.erase(victim);
    }
    aclCache_[addr] = decision;
    return decision;
}

void UdpSessionEntry::initConnLocked(const proto::UDPMessage& firstMsg) {
    // Caller must hold connMutex_.
    if (closed_) {
        throw Error("session is closed");
    }

    std::string actualAddr;
    std::shared_ptr<IUdpConn> c;
    try {
        c = DialFunc(firstMsg.Addr, firstMsg.Data, actualAddr);
    } catch (const std::exception& e) {
        // Fail fast if DialFunc failed
        // (usually indicates the connection has been rejected by the ACL)
        // CloseWithErr acquires connMutex_ again (recursive).
        CloseWithErr(e.what());
        throw;
    }

    conn_ = c;

    if (firstMsg.Addr != actualAddr) {
        // Hook changed the address, enable address override
        OverrideAddr = actualAddr;
        OriginalAddr = firstMsg.Addr;
    }
    bool expected = false;
    if (receiveLoopStarted_.compare_exchange_strong(expected, true)) {
        auto self = shared_from_this(); // keep the entry alive for the loop
        receiveThread_ = std::thread([self]() { self->receiveLoop(); });
        receiveThreadId_ = receiveThread_.get_id();
    }
}

void UdpSessionEntry::receiveLoop() {
    // Snapshot the connection pointer once: conn_ is set exactly once (before
    // this thread starts) and never reassigned, but a local copy removes any
    // doubt about concurrent member access. Object-level Close()/ReadFrom()
    // synchronization is guaranteed by the IUdpConn contract.
    std::shared_ptr<IUdpConn> conn;
    {
        std::lock_guard<std::recursive_mutex> lk(connMutex_);
        conn = conn_;
    }
    std::vector<uint8_t> udpBuf(proto::kMaxUDPSize);
    std::vector<uint8_t> msgBuf(proto::kMaxUDPSize);
    for (;;) {
        std::string rAddr;
        size_t udpN = 0;
        try {
            udpN = conn->ReadFrom(udpBuf.data(), udpBuf.size(), rAddr);
        } catch (const std::exception& e) {
            CloseWithErr(e.what());
            return;
        } catch (...) {
            // No exception may ever escape a thread function - that would be
            // an instant std::terminate / fast-fail abort.
            CloseWithErr("unknown receive error");
            return;
        }
        Last.Set(MonoTime::Now().ns);

        if (!OriginalAddr.empty()) {
            // Use the original address in the opposite direction,
            // otherwise the QUIC clients or NAT on the client side
            // may not treat it as the same UDP session.
            rAddr = OriginalAddr;
        }

        proto::UDPMessage msg;
        msg.SessionID = ID;
        msg.PacketID = 0;
        msg.FragID = 0;
        msg.FragCount = 1;
        msg.Addr = rAddr;
        msg.Data.assign(udpBuf.begin(), udpBuf.begin() + static_cast<long>(udpN));
        try {
            SendMessageAutoFrag(*IO, msgBuf.data(), msgBuf.size(), msg);
        } catch (const std::exception& e) {
            CloseWithErr(e.what());
            return;
        } catch (...) {
            CloseWithErr("unknown send error");
            return;
        }
    }
}

void SendMessageAutoFrag(UdpIO& io, uint8_t* buf, size_t bufLen, proto::UDPMessage& msg) {
    try {
        io.SendMessage(buf, bufLen, msg);
    } catch (const DatagramTooLargeError& e) {
        // Message too large, try fragmentation
        msg.PacketID = static_cast<uint16_t>(RandomUint64() % 0xFFFF) + 1;
        auto fMsgs = frag::FragUDPMessage(msg, static_cast<size_t>(e.MaxDatagramPayloadSize));
        for (const auto& fMsg : fMsgs) {
            io.SendMessage(buf, bufLen, fMsg);
        }
    }
}

// ---------------------------------------------------------------------------
// UdpSessionManager

UdpSessionManager::UdpSessionManager(UdpIO* io, UdpEventLogger* eventLogger,
                                     Duration idleTimeout)
    : io_(io), eventLogger_(eventLogger), idleTimeout_(idleTimeout) {
    // Start the idle-cleanup ticker immediately (mirrors Go where Run()
    // launches it - our direct-construction tests rely on cleanup without
    // calling Run(); Run() itself does NOT spawn a second one).
    std::lock_guard<std::mutex> lk(ctlMutex_);
    if (!stopFlag_.load(std::memory_order_relaxed)) {
        cleanerThread_ = std::thread(&UdpSessionManager::idleCleanupLoop, this);
    }
}

std::shared_ptr<UdpSessionManager> UdpSessionManager::Create(
    std::shared_ptr<UdpIO> io, std::shared_ptr<UdpEventLogger> eventLogger,
    Duration idleTimeout) {
    auto mgr = std::shared_ptr<UdpSessionManager>(
        new UdpSessionManager(io.get(), eventLogger.get(), idleTimeout));
    // Keep io/logger alive as long as the manager (and its run thread) lives.
    mgr->ioKeep_ = std::move(io);
    mgr->eventLoggerKeep_ = std::move(eventLogger);
    auto self = mgr->shared_from_this();
    std::thread([self] {
        try {
            self->Run();
        } catch (...) {
            // No exception may escape a thread function.
        }
    }).detach();
    return mgr;
}

UdpSessionManager::~UdpSessionManager() { Stop(); }

void UdpSessionManager::Run() {
    // Cleaner already started by the constructor; nothing to do here.
    for (;;) {
        try {
            auto msg = io_->ReceiveMessage(); // throws when the connection closes
            feed(msg);
        } catch (...) {
            break;
        }
    }
    try {
        Stop();
    } catch (...) {
        // Never let an exception escape the run thread (std::terminate).
    }
}

void UdpSessionManager::Stop() {
    std::thread cleaner;
    {
        std::lock_guard<std::mutex> lk(ctlMutex_);
        bool expected = false;
        if (!stopFlag_.compare_exchange_strong(expected, true)) {
            return; // already stopped
        }
        cleaner = std::move(cleanerThread_);
    }
    if (cleaner.joinable()) {
        cleaner.join();
    }
    cleanup(false);

    // Deterministic shutdown (#2): close connections above makes every
    // receive loop exit (IUdpConn contract); wait for the loops to finish so
    // no thread can touch io_/eventLogger_ after this point.
    for (;;) {
        std::vector<std::shared_ptr<UdpSessionEntry>> snapshot;
        {
            std::lock_guard<std::mutex> lk(registryMutex_);
            snapshot = liveEntries_;
        }
        if (snapshot.empty()) break;
        for (auto& entry : snapshot) {
            entry->JoinReceiveLoopForShutdown();
            std::lock_guard<std::mutex> lk(registryMutex_);
            std::erase(liveEntries_, entry);
        }
    }
}

void UdpSessionManager::idleCleanupLoop() {
    while (!stopFlag_.load(std::memory_order_acquire)) {
        SleepFor(Duration(kIdleCleanupIntervalNs));
        try {
            cleanup(true);
        } catch (...) {
            // The cleaner must never die from an escaping exception
            // (user-supplied logger/hook callbacks may throw).
        }
    }
}

void UdpSessionManager::cleanup(bool idleOnly) {
    // We use a plain lock scan here; entries remove themselves from the map
    // inside ExitFunc (which locks again).
    std::vector<std::shared_ptr<UdpSessionEntry>> timeoutEntries;
    {
        std::shared_lock<std::shared_mutex> lk(mutex_);
        int64_t nowNs = MonoTime::Now().ns;
        for (auto& [id, entry] : m_) {
            if (!idleOnly || nowNs - entry->Last.Get() > idleTimeout_.ns) {
                timeoutEntries.push_back(entry);
            }
        }
    }

    for (auto& entry : timeoutEntries) {
        // This eventually calls ExitFunc,
        // where the mutex will be locked again to remove the entry from the map.
        entry->CloseWithErr("");
    }
}

void UdpSessionManager::feed(std::shared_ptr<proto::UDPMessage> msg) {
    std::shared_ptr<UdpSessionEntry> entry;
    {
        std::shared_lock<std::shared_mutex> lk(mutex_);
        auto it = m_.find(msg->SessionID);
        if (it != m_.end()) entry = it->second;
    }

    // Create a new session if not exists
    if (!entry) {
        uint32_t sid = msg->SessionID;
        // Two dispatch modes:
        //  - managed mode (Create): callbacks lock a weak_ptr, so an entry
        //    outliving the manager cannot touch freed state.
        //  - direct mode (tests): no shared ownership exists; capture raw
        //    this - valid because such users guarantee the manager outlives
        //    every entry (Stop() joins all receive loops first).
        auto selfw = weak_from_this();
        const bool managed = !selfw.expired();
        UdpSessionManager* rawThis = this;

        auto dialFunc = [selfw, managed, rawThis, sid](
                            const std::string& addr,
                            const std::vector<uint8_t>& firstMsgData,
                            std::string& actualAddr) -> std::shared_ptr<IUdpConn> {
            UdpSessionManager* m = managed ? selfw.lock().get() : rawThis;
            if (!m) throw Error("session manager is gone");
            return m->DialFor(sid, addr, firstMsgData, actualAddr);
        };
        auto exitFunc = [selfw, managed, rawThis, sid](const std::string& err) {
            UdpSessionManager* m = managed ? selfw.lock().get() : rawThis;
            if (m) m->ExitFor(sid, err);
        };

        entry = std::make_shared<UdpSessionEntry>(sid, io_, dialFunc, exitFunc, ioKeep_);

        // Insert the session into the map and the live registry
        {
            std::unique_lock<std::shared_mutex> lk(mutex_);
            m_[sid] = entry;
        }
        std::lock_guard<std::mutex> rlk(registryMutex_);
        liveEntries_.push_back(entry);
    }

    // Feed the message to the session
    // Feed (send) errors are ignored for now,
    // as some are temporary (e.g. invalid address)
    try {
        entry->Feed(msg);
    } catch (...) {
    }
}

std::shared_ptr<IUdpConn> UdpSessionManager::DialFor(uint32_t sid,
                                                     const std::string& addr,
                                                     const std::vector<uint8_t>& firstMsgData,
                                                     std::string& actualAddr) {
    // Call the hook
    std::vector<uint8_t> data = firstMsgData;
    std::string a = addr;
    io_->Hook(data, a);
    actualAddr = a;
    // Log the event
    eventLogger_->New(sid, a);
    // Dial target
    return io_->UDP(a);
}

void UdpSessionManager::ExitFor(uint32_t sid, const std::string& err) {
    // Log the event
    eventLogger_->Close(sid, err);

    // Remove the session from the map and the live registry
    {
        std::unique_lock<std::shared_mutex> lk(mutex_);
        m_.erase(sid);
    }
    std::lock_guard<std::mutex> rlk(registryMutex_);
    std::erase_if(liveEntries_, [sid](const std::shared_ptr<UdpSessionEntry>& e) {
        return e->ID == sid;
    });
}

size_t UdpSessionManager::Count() {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return m_.size();
}

} // namespace hy2::server
