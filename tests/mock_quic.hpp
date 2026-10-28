// mock_quic.hpp - In-memory QUIC connection/stream mocks used by session tests.
#pragma once

#include <atomic>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "hy2/quic.hpp"
#include "hy2/server_iface.hpp"

namespace hytest {

// PipeStream: a full-duplex in-memory byte stream connected to a peer.
//
// Peers reference each other through weak_ptr (no ownership cycle): dropping
// one side really destroys it, and every cross-access locks the weak ref so
// teardown can never touch a freed peer.
class PipeStream : public hy2::IQuicStream {
public:
    static std::pair<std::shared_ptr<PipeStream>, std::shared_ptr<PipeStream>> MakePair() {
        auto a = std::make_shared<PipeStream>();
        auto b = std::make_shared<PipeStream>();
        a->wpeer_ = b;
        b->wpeer_ = a;
        return {a, b};
    }

    ~PipeStream() override {
        // Avoid accessing peer in destructor — peer may already be destroyed.
        // Just mark our sides as closed without signaling peer.
        std::lock_guard<std::mutex> lk(mu_);
        if (!closed_) {
            closed_ = true;
            closedReadSide_ = true;
            chunks_.emplace_back(); // EOF marker
            cv_.notify_all();
        }
    }

    size_t Read(uint8_t* p, size_t n) override {
        for (;;) {
            std::vector<uint8_t> chunk;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&] { return closedReadSide_ || !chunks_.empty(); });
                if (chunks_.empty()) {
                    throw hy2::Error("stream closed"); // read side woken by Close
                }
                chunk = std::move(chunks_.front());
                chunks_.pop_front();
            }
            if (chunk.empty()) {
                return 0; // EOF marker
            }
            size_t got = std::min(n, chunk.size());
            std::memcpy(p, chunk.data(), got);
            // push back remainder
            if (got < chunk.size()) {
                std::lock_guard<std::mutex> lk(mu_);
                chunk.erase(chunk.begin(), chunk.begin() + static_cast<long>(got));
                chunks_.push_front(std::move(chunk));
            }
            return got;
        }
    }

    void Write(const uint8_t* p, size_t n) override {
        auto peer = wpeer_.lock();
        if (!peer) throw hy2::Error("no peer");
        if (writeClosed_) throw hy2::Error("write closed");
        std::lock_guard<std::mutex> lk(peer->mu_);
        peer->chunks_.push_back(std::vector<uint8_t>(p, p + n));
        peer->cv_.notify_one();
    }

    void CloseWrite() override {
        if (writeClosed_.exchange(true)) return;
        if (auto peer = wpeer_.lock()) {
            std::lock_guard<std::mutex> lk(peer->mu_);
            if (!peer->peerClosedWrite_) {
                peer->peerClosedWrite_ = true;
                peer->chunks_.emplace_back();
                peer->cv_.notify_all();
            }
        }
    }

    void Close() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!closed_) {
                closed_ = true;
                closedReadSide_ = true;
                chunks_.emplace_back(); // EOF marker
                cv_.notify_all();
            }
        }
        // Signal the peer's reads too (our write side closing == their read EOF).
        if (auto peer = wpeer_.lock()) {
            std::lock_guard<std::mutex> plk(peer->mu_);
            if (!peer->peerClosedWrite_) {
                peer->peerClosedWrite_ = true;
                peer->chunks_.emplace_back();
                peer->cv_.notify_all();
            }
        }
    }

    void CancelRead(hy2::StreamErrorCode) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            closedReadSide_ = true;
            chunks_.emplace_back(); // EOF marker
        }
        cv_.notify_all();
    }

    void CancelWrite(hy2::StreamErrorCode) override {
        writeClosed_ = true;
    }

    uint64_t StreamID() const override { return id_; }

    void SetID(uint64_t id) { id_ = id; }

private:
    uint64_t id_ = 0;
    std::weak_ptr<PipeStream> wpeer_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::vector<uint8_t>> chunks_;
    bool closed_ = false;
    bool closedReadSide_ = false;
    std::atomic<bool> writeClosed_{false};
    bool peerClosedWrite_ = false;
};

// MockUdpConn records written packets; can be fed inbound packets.
class MockUdpConn : public hy2::server::IUdpConn {
public:
    struct Packet {
        std::vector<uint8_t> Data;
        std::string Addr;
    };

    size_t ReadFrom(uint8_t* buf, size_t len, std::string& addr) override {
        for (;;) {
            Packet pkt;
            {
                std::unique_lock<std::mutex> lk(mu_);
                // Use wait_for to periodically recheck the predicate, preventing
                // lost notifications when Close() fires between predicate check
                // and entering the wait state.
                while (!closed_ && inbound_.empty()) {
                    cv_.wait_for(lk, std::chrono::milliseconds(100));
                }
                if (closed_ && inbound_.empty()) {
                    throw hy2::Error("udp conn closed");
                }
                pkt = std::move(inbound_.front());
                inbound_.pop_front();
            }
            size_t n = std::min(len, pkt.Data.size());
            std::memcpy(buf, pkt.Data.data(), n);
            addr = pkt.Addr;
            return n;
        }
    }

    void WriteTo(const uint8_t* buf, size_t len, const std::string& addr) override {
        std::lock_guard<std::mutex> lk(mu_);
        written_.push_back(Packet{std::vector<uint8_t>(buf, buf + len), addr});
    }

    void Close() override {
        std::lock_guard<std::mutex> lk(mu_);
        closed_ = true;
        cv_.notify_all();
    }

    void Inject(std::vector<uint8_t> data, const std::string& addr) {
        std::lock_guard<std::mutex> lk(mu_);
        inbound_.push_back(Packet{std::move(data), addr});
        cv_.notify_one();
    }

    std::vector<Packet> Written() {
        std::lock_guard<std::mutex> lk(mu_);
        return written_;
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Packet> inbound_;
    std::vector<Packet> written_;
    bool closed_ = false;
};

// MockQuicConnection: datagrams recorded/injected; streams opened are queued.
class MockQuicConnection : public hy2::IQuicConnection {
public:
    size_t openCount = 0;

    std::shared_ptr<hy2::IQuicStream> OpenStream() override {
        auto [a, b] = PipeStream::MakePair();
        a->SetID(nextStreamId_++);
        {
            std::lock_guard<std::mutex> lk(mu_);
            openedStreams_.push_back(b); // server-side end
        }
        openCount++;
        openedCv_.notify_all();
        return a;
    }

    std::shared_ptr<hy2::IQuicStream> AcceptStream() override {
        std::unique_lock<std::mutex> lk(mu_);
        acceptCv_.wait(lk, [&] { return !incomingStreams_.empty() || closed_; });
        if (incomingStreams_.empty()) throw hy2::Error("connection closed");
        auto s = incomingStreams_.front();
        incomingStreams_.pop_front();
        return s;
    }

    // Injects a stream as if received from the wire.
    void InjectIncomingStream(std::shared_ptr<hy2::IQuicStream> s) {
        std::lock_guard<std::mutex> lk(mu_);
        incomingStreams_.push_back(std::move(s));
        acceptCv_.notify_one();
    }

    // Waits until OpenStream has been called n times or timeoutMs elapses.
    bool WaitForOpens(size_t n, int timeoutMs = 2000) {
        std::unique_lock<std::mutex> lk(mu_);
        return openedCv_.wait_for(lk, std::chrono::milliseconds(timeoutMs),
                                  [&] { return openCount >= n; });
    }

    void SendDatagram(const uint8_t* p, size_t n) override {
        if (n > (size_t)maxDatagramPayloadSize_) {
            throw hy2::DatagramTooLargeError(maxDatagramPayloadSize_);
        }
        std::lock_guard<std::mutex> lk(mu_);
        auto data = std::vector<uint8_t>(p, p + n);
        sentDatagrams_.push_back(data);
        receivedDatagrams_.push_back(std::vector<uint8_t>(data)); // echo for local test
        datagramCv_.notify_all();
    }

    std::vector<uint8_t> ReceiveDatagram() override {
        std::unique_lock<std::mutex> lk(mu_);
        datagramCv_.wait(lk, [&] { return closed_ || !receivedDatagrams_.empty(); });
        if (receivedDatagrams_.empty()) throw hy2::Error("connection closed");
        auto v = std::move(receivedDatagrams_.front());
        receivedDatagrams_.pop_front();
        return v;
    }

    void InjectDatagram(std::vector<uint8_t> data) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            receivedDatagrams_.push_back(std::move(data));
        }
        datagramCv_.notify_one();
    }

    size_t SentDatagramCount() {
        std::lock_guard<std::mutex> lk(mu_);
        return sentDatagrams_.size();
    }

    std::vector<std::vector<uint8_t>> SentDatagrams() {
        std::lock_guard<std::mutex> lk(mu_);
        return sentDatagrams_;
    }

    // Waits for at least n sent datagrams.
    bool WaitForSentDatagrams(size_t n, int timeoutMs = 2000) {
        std::unique_lock<std::mutex> lk(mu_);
        return datagramCv_.wait_for(lk, std::chrono::milliseconds(timeoutMs),
                                    [&] { return sentDatagrams_.size() >= n; });
    }

    void CloseWithError(uint64_t errorCode, const std::string& reason) override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            closed_ = true;
            lastErrorCode_ = errorCode;
            lastErrorReason_ = reason;
        }
        datagramCv_.notify_all();
        acceptCv_.notify_all();
    }

    std::string LocalAddr() const override { return localAddr_; }
    std::string RemoteAddr() const override { return remoteAddr_; }

    int64_t maxDatagramPayloadSize_ = 1200;
    std::string localAddr_ = "198.51.100.2:40000";
    std::string remoteAddr_ = "203.0.113.7:443";
    uint64_t LastErrorCode() const { return lastErrorCode_; }
    bool WasClosed() const {
        std::lock_guard<std::mutex> lk(mu_);
        return closed_;
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::condition_variable acceptCv_;
    std::condition_variable datagramCv_;
    std::condition_variable openedCv_;
    std::deque<std::shared_ptr<hy2::IQuicStream>> incomingStreams_;
    std::deque<std::shared_ptr<hy2::IQuicStream>> openedStreams_;
    std::deque<std::vector<uint8_t>> receivedDatagrams_;
    std::vector<std::vector<uint8_t>> sentDatagrams_;
    uint64_t nextStreamId_ = 0;
    uint64_t lastErrorCode_ = 0;
    std::string lastErrorReason_;
    bool closed_ = false;
};

} // namespace hytest
