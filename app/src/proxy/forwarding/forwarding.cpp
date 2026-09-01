// forwarding.cpp - TCP/UDP forwarding using Hysteria2 client as outbound.
// Rewrite of app/internal/forwarding/tcp.go + udp.go.
// Cross-platform: no platform-specific code.
#include "hy2/proxy/forwarding/forwarding.hpp"

#include <algorithm>
#include <cstring>
#include <thread>

namespace hy2::proxy::forwarding {

namespace {

// Bidirectional copy between two byte reader/writers
void bidirectionalCopy(std::shared_ptr<hy2::IByteReaderWriter> a,
                       std::shared_ptr<hy2::IByteReaderWriter> b) {
    std::atomic<bool> done{false};
    auto copier = [&](std::shared_ptr<hy2::IByteReaderWriter> src,
                      std::shared_ptr<hy2::IByteReaderWriter> dst) {
        uint8_t buf[4096];
        while (!done.load(std::memory_order_relaxed)) {
            size_t n = src->Read(buf, sizeof(buf));
            if (n == 0) break;
            try {
                dst->Write(buf, n);
            } catch (...) {
                break;
            }
        }
        done.store(true, std::memory_order_relaxed);
        // Unblock the other direction's blocking Read. Without closing the
        // peer side it stays parked in src->Read() until the remote closes
        // (which never happens for e.g. HTTP keep-alive), so join() below
        // would hang forever. Mirrors core CopyTwoWay's closeQuietly teardown.
        try { a->Close(); } catch (...) {}
        try { b->Close(); } catch (...) {}
    };

    std::thread t1(copier, a, b);
    std::thread t2(copier, b, a);
    t1.join();
    t2.join();
}

// Get monotonic time in nanoseconds
int64_t nowNs() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// TcpTunnel

void TcpTunnel::handle(std::shared_ptr<server::IConn> conn) {
    if (EventLogger) {
        EventLogger->Connect("");
    }

    std::string err;
    try {
        auto rConn = HyClient->TCP(Remote);
        // IConn inherits IByteReaderWriter, so static_pointer_cast is safe
        auto connRw = std::static_pointer_cast<hy2::IByteReaderWriter>(conn);
        bidirectionalCopy(connRw, rConn);
    } catch (const std::exception& e) {
        err = e.what();
    }

    if (EventLogger) {
        EventLogger->Error("", err);
    }
}

// ---------------------------------------------------------------------------
// UdpSessionEntry

void UdpSessionEntry::Feed(const uint8_t* data, size_t len, const std::string& remote) {
    LastActiveNs.store(nowNs(), std::memory_order_release);
    try {
        HyConn->Send(data, len, remote);
    } catch (...) {
        // Send failed, session will timeout
    }
}

void UdpSessionEntry::ReceiveLoop(std::shared_ptr<server::IUdpConn> localConn,
                                   const std::string& clientAddr) {
    try {
        while (true) {
            std::vector<uint8_t> data;
            std::string from;
            bool ok = HyConn->Receive(data, from);
            if (!ok) break;

            LastActiveNs.store(nowNs(), std::memory_order_release);

            // Send to local client
            try {
                localConn->WriteTo(data.data(), data.size(), clientAddr);
            } catch (...) {
                break;
            }
        }
    } catch (...) {
        // Receive failed
    }
}

// ---------------------------------------------------------------------------
// UdpTunnel

void UdpTunnel::Serve(std::shared_ptr<server::IUdpConn> localConn) {
    // Start idle cleanup thread
    std::atomic<bool> stop{false};
    std::thread cleanupThread([this, localConn, &stop] {
        idleCleanupLoop(localConn, stop);
    });

    // Read loop
    uint8_t buf[4096];
    while (!stop.load(std::memory_order_acquire)) {
        std::string clientAddr;
        size_t n = localConn->ReadFrom(buf, sizeof(buf), clientAddr);
        if (n == 0) break;

        feed(localConn, clientAddr, buf, n);
    }

    stop.store(true, std::memory_order_release);
    cleanupThread.join();
}

void UdpTunnel::feed(std::shared_ptr<server::IUdpConn> localConn,
                      const std::string& clientAddr,
                      const uint8_t* data, size_t len) {
    std::shared_ptr<UdpSessionEntry> entry;

    // Lookup existing session
    {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = sessions_.find(clientAddr);
        if (it != sessions_.end()) {
            entry = it->second;
        }
    }

    if (!entry) {
        // Create new session
        try {
            auto hyConn = HyClient->UDP();
            entry = std::make_shared<UdpSessionEntry>();
            entry->HyConn = std::move(hyConn);
            entry->LastActiveNs.store(nowNs(), std::memory_order_release);

            // Start receive loop
            std::thread([this, entry, localConn, clientAddr]() {
                entry->ReceiveLoop(localConn, clientAddr);
                // On exit: remove from sessions map
                std::lock_guard<std::mutex> lk(mutex_);
                sessions_.erase(clientAddr);
            }).detach();

            // Insert into map
            {
                std::lock_guard<std::mutex> lk(mutex_);
                sessions_[clientAddr] = entry;
            }

            if (EventLogger) {
                EventLogger->Connect(clientAddr);
            }
        } catch (...) {
            if (EventLogger) {
                EventLogger->Error(clientAddr, "failed to create UDP session");
            }
            return;
        }
    }

    // Feed data
    entry->Feed(data, len, Remote);
}

void UdpTunnel::idleCleanupLoop(std::shared_ptr<server::IUdpConn> /*localConn*/,
                                 std::atomic<bool>& stop) {
    while (!stop.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop.load(std::memory_order_acquire)) break;

        int64_t now = nowNs();
        std::lock_guard<std::mutex> lk(mutex_);
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            int64_t last = it->second->LastActiveNs.load(std::memory_order_acquire);
            if (now - last > TimeoutNs) {
                it->second->Timeout.store(true, std::memory_order_release);
                try { it->second->HyConn->Close(); } catch (...) {}
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

} // namespace hy2::proxy::forwarding
