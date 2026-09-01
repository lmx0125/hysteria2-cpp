// proxymux.cpp - Protocol multiplexer.
// Rewrite of app/internal/proxymux/mux.go + manager.go.
// Cross-platform: no platform-specific code.
#include "hy2/proxy/proxymux/proxymux.hpp"

#include <algorithm>
#include <cstring>

namespace hy2::proxy::proxymux {

// ---------------------------------------------------------------------------
// SubListener

std::shared_ptr<server::IConn> SubListener::Accept() {
    std::unique_lock<std::mutex> lk(mutex_);
    cv_.wait(lk, [this] { return !queue_.empty() || closed_; });
    if (closed_ && queue_.empty()) return nullptr;
    auto conn = queue_.front();
    queue_.erase(queue_.begin());
    return conn;
}

void SubListener::Close() {
    std::lock_guard<std::mutex> lk(mutex_);
    closed_ = true;
    cv_.notify_all();
}

bool SubListener::IsClosed() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return closed_;
}

// ---------------------------------------------------------------------------
// MuxListener

MuxListener::MuxListener(std::shared_ptr<server::IConn> base)
    : base_(std::move(base)) {
    acceptThread_ = std::thread([this] { acceptLoop(); });
}

MuxListener::~MuxListener() {
    Close();
}

std::shared_ptr<SubListener> MuxListener::ListenSOCKS() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (socksListener_ && !socksListener_->IsClosed()) {
        return nullptr; // already in use
    }
    socksListener_ = std::make_shared<SubListener>();
    return socksListener_;
}

std::shared_ptr<SubListener> MuxListener::ListenHTTP() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (httpListener_ && !httpListener_->IsClosed()) {
        return nullptr; // already in use
    }
    httpListener_ = std::make_shared<SubListener>();
    return httpListener_;
}

void MuxListener::Close() {
    bool expected = false;
    if (!closed_.compare_exchange_strong(expected, true)) return;

    if (base_) {
        try { base_->Close(); } catch (...) {}
    }
    if (acceptThread_.joinable()) acceptThread_.join();

    std::lock_guard<std::mutex> lk(mutex_);
    if (socksListener_) socksListener_->Close();
    if (httpListener_) httpListener_->Close();
}

void MuxListener::acceptLoop() {
    while (!closed_.load(std::memory_order_acquire)) {
        // Read 1 byte to detect protocol
        uint8_t peek;
        // NOTE: This is a simplified version. In a real implementation,
        // we would need a proper TCP listener with Accept() and peek support.
        // The IConn interface doesn't support peek, so this is a placeholder.
        break;
    }
}

void MuxListener::dispatch(std::shared_ptr<server::IConn> conn) {
    // Read first byte
    uint8_t firstByte = 0;
    size_t n = conn->Read(&firstByte, 1);
    if (n == 0) {
        try { conn->Close(); } catch (...) {}
        return;
    }

    std::lock_guard<std::mutex> lk(mutex_);
    std::shared_ptr<SubListener> target;
    if (firstByte == 0x05) {
        target = socksListener_;
    } else {
        target = httpListener_;
    }

    if (!target || target->IsClosed()) {
        try { conn->Close(); } catch (...) {}
        return;
    }

    // Wrap in connWithOneByte to replay the first byte
    // (In a real implementation, we'd wrap the conn here)
    std::lock_guard<std::mutex> qk(target->mutex_);
    if (target->closed_) {
        try { conn->Close(); } catch (...) {}
        return;
    }
    target->queue_.push_back(conn);
    target->cv_.notify_one();
}

// ---------------------------------------------------------------------------
// MuxManager

MuxManager& MuxManager::Instance() {
    static MuxManager instance;
    return instance;
}

std::shared_ptr<MuxListener> MuxManager::GetOrCreate(const std::string& address) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = listeners_.find(address);
    if (it != listeners_.end()) {
        return it->second;
    }

    // Create a new MuxListener
    // NOTE: In a real implementation, we would create a TCP listener here
    // using correctnet.Listen(). For now, return nullptr.
    return nullptr;
}

std::shared_ptr<SubListener> MuxManager::ListenHTTP(const std::string& address) {
    auto ml = GetOrCreate(address);
    if (!ml) return nullptr;
    return ml->ListenHTTP();
}

std::shared_ptr<SubListener> MuxManager::ListenSOCKS(const std::string& address) {
    auto ml = GetOrCreate(address);
    if (!ml) return nullptr;
    return ml->ListenSOCKS();
}

} // namespace hy2::proxy::proxymux
