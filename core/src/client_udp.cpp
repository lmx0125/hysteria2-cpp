// client_udp.cpp - rewrite of core/client/udp.go
#include "hy2/client_udp.hpp"

#include <thread>

namespace hy2::client {

// ---------------------------------------------------------------------------
// UdpConn

UdpConn::UdpConn(uint32_t id, std::shared_ptr<UdpIO> io)
    : ID(id), IO(std::move(io)),
      ReceiveCh(std::make_shared<Channel<std::shared_ptr<proto::UDPMessage>>>(
          kUdpMessageChanSize)) {}

UdpRecvResult UdpConn::ReceivePacket(std::vector<uint8_t>& data, std::string& addr,
                                     Duration timeout) {
    // One deadline for the whole call, not one per loop iteration: a fragment
    // arriving every 60 ms would otherwise keep pushing the deadline forward
    // and the caller's timeout would never fire.
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::nanoseconds(timeout.ns);
    for (;;) {
        std::shared_ptr<proto::UDPMessage> msg;
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero()) {
            return UdpRecvResult::kTimeout;
        }
        if (!ReceiveCh->ReceiveFor(msg, remaining)) {
            // ReceiveFor only reports false on timeout or closed-and-drained.
            return ReceiveCh->Closed() ? UdpRecvResult::kClosed
                                       : UdpRecvResult::kTimeout;
        }
        auto dfMsg = D.Feed(std::move(msg));
        if (!dfMsg) {
            // Incomplete message, wait for more
            continue;
        }
        // Sole owner (the channel handed us its only reference): move the
        // payload out instead of copying it into the caller's buffers (H4/M6).
        data = std::move(dfMsg->Data);
        addr = std::move(dfMsg->Addr);
        return UdpRecvResult::kPacket;
    }
}

bool UdpConn::Receive(std::vector<uint8_t>& data, std::string& addr) {
    return ReceivePacket(data, addr,
                         Duration::FromMillis(kReceiveTimeout.count())) ==
           UdpRecvResult::kPacket;
}

void UdpConn::Send(const uint8_t* data, size_t n, const std::string& addr) {
    if (closed_.load()) {
        throw Error("connection closed");
    }
    // Reused across calls on this thread (one UdpConn writer thread, and
    // possibly several UdpConns on it): no per-datagram allocation for the
    // message payload or the serialization buffer after the first call.
    thread_local proto::UDPMessage msg;
    thread_local std::vector<uint8_t> sendBuf(proto::kMaxUDPSize);
    msg.SessionID = ID;
    msg.PacketID = 0;
    msg.FragID = 0;
    msg.FragCount = 1;
    msg.Addr = addr;
    msg.Data.assign(data, data + n);
    try {
        IO->SendMessage(sendBuf.data(), sendBuf.size(), msg);
    } catch (const DatagramTooLargeError& e) {
        // Message too large, try fragmentation
        msg.PacketID = static_cast<uint16_t>(RandomUint64() % 0xFFFF) + 1;
        auto fMsgs = frag::FragUDPMessage(msg, static_cast<size_t>(e.MaxDatagramPayloadSize));
        for (const auto& fMsg : fMsgs) {
            IO->SendMessage(sendBuf.data(), sendBuf.size(), fMsg);
        }
    }
}

void UdpConn::Close() {
    closed_.store(true);
    // Also close the channel, so a thread already parked in ReceivePacket()
    // is woken and observes the close instead of waiting out its whole
    // deadline. Setting the flag alone left it sleeping: Close() is called
    // from the caller's teardown thread (and from closeCleanup on connection
    // loss), which is exactly when a receiver must not linger.
    ReceiveCh->Close();
}

// ---------------------------------------------------------------------------
// ClientUdpSessionManager

ClientUdpSessionManager::ClientUdpSessionManager(std::shared_ptr<UdpIO> io)
    : io_(std::move(io)) {}

std::shared_ptr<ClientUdpSessionManager> ClientUdpSessionManager::Create(std::shared_ptr<UdpIO> io) {
    // Factory so the receive loop can hold shared ownership
    // (shared_from_this() is not usable inside a constructor).
    auto mgr = std::shared_ptr<ClientUdpSessionManager>(new ClientUdpSessionManager(io));
    auto self = mgr->shared_from_this();
    std::thread([self]() {
        try {
            self->run();
        } catch (...) {
            // No exception may escape a thread function.
        }
    }).detach();
    return mgr;
}

ClientUdpSessionManager::~ClientUdpSessionManager() = default;

void ClientUdpSessionManager::run() {
    try {
        for (;;) {
            auto msg = io_->ReceiveMessage(); // throws when the connection closes
            feed(msg);
        }
    } catch (...) {
    }
    closeCleanup();
}

void ClientUdpSessionManager::closeCleanup() {
    std::unique_lock<std::shared_mutex> lk(mutex_);

    std::vector<std::shared_ptr<UdpConn>> all;
    all.reserve(m_.size());
    for (auto& [id, conn] : m_) {
        all.push_back(conn);
    }
    for (auto& conn : all) {
        closeConn(conn);
    }
    closed_ = true;
}

void ClientUdpSessionManager::feed(std::shared_ptr<proto::UDPMessage> msg) {
    std::shared_lock<std::shared_mutex> lk(mutex_);

    auto it = m_.find(msg->SessionID);
    if (it == m_.end()) {
        // Ignore message from unknown session
        return;
    }

    it->second->ReceiveCh->TrySend(msg); // drops when full (select/default in Go)
}

std::shared_ptr<HyUDPConn> ClientUdpSessionManager::NewUDP() {
    std::unique_lock<std::shared_mutex> lk(mutex_);

    if (closed_) {
        throw ClosedError();
    }

    uint32_t id = nextID_++;

    auto conn = std::make_shared<UdpConn>(id, io_);
    m_[id] = conn;

    return conn;
}

void ClientUdpSessionManager::closeConn(const std::shared_ptr<UdpConn>& conn) {
    if (!conn->IsClosed()) {
        conn->closed_.store(true);
        conn->ReceiveCh->Close();
        m_.erase(conn->ID);
    }
}

size_t ClientUdpSessionManager::Count() {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return m_.size();
}

} // namespace hy2::client
