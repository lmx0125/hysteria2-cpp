// gecko.cpp - Port of extras/obfs/gecko_frame.go and gecko.go.
#include "hy2/obfs/gecko.hpp"

#include <chrono>
#include <cstring>
#include <utility>

#include "hy2/common.hpp"
#include "hy2/error.hpp"
#include "hy2/obfs/salamander.hpp"

namespace hy2::obfs {
namespace {

// randIntn from gecko.go: uniform random int in [0, n).
int RandIntn(int n) {
    if (n <= 1) {
        return 0;
    }
    return static_cast<int>(RandomUint32() % static_cast<uint32_t>(n));
}

int RandomFragmentChunks() {
    return kGeckoMinFragmentChunks +
           RandIntn(kGeckoMaxFragmentChunks - kGeckoMinFragmentChunks + 1);
}

} // namespace

size_t EncodeFrame(const FrameHeader& h, const uint8_t* payload, size_t payloadLen,
                   uint8_t* out, size_t outCap) {
    if (h.totalChunks < kGeckoMinFragmentChunks || h.totalChunks > kGeckoMaxFragmentChunks) {
        throw Error("gecko frame invalid");
    }
    if (h.chunkIdx >= h.totalChunks) {
        throw Error("gecko frame invalid");
    }
    const size_t needed =
        static_cast<size_t>(kGeckoHeaderSize) + h.padLen + payloadLen;
    if (outCap < needed) {
        throw Error("gecko frame truncated");
    }
    out[0] = kGeckoFlagFragment;
    out[1] = h.msgID;
    out[2] = static_cast<uint8_t>(h.chunkIdx << 4) | (h.totalChunks & 0x0f);
    out[3] = static_cast<uint8_t>(h.padLen >> 8);
    out[4] = static_cast<uint8_t>(h.padLen);
    RandomBytes(out + kGeckoHeaderSize, h.padLen);
    if (payloadLen > 0) {
        std::memcpy(out + kGeckoHeaderSize + h.padLen, payload, payloadLen);
    }
    return needed;
}

DecodedFrame DecodeFrame(const uint8_t* in, size_t len) {
    if (len < static_cast<size_t>(kGeckoHeaderSize)) {
        throw Error("gecko frame truncated");
    }
    if ((in[0] & kGeckoFlagFragment) == 0) {
        throw Error("gecko frame invalid");
    }
    DecodedFrame f;
    f.header.msgID = in[1];
    f.header.chunkIdx = in[2] >> 4;
    f.header.totalChunks = in[2] & 0x0f;
    f.header.padLen = static_cast<uint16_t>((static_cast<uint16_t>(in[3]) << 8) | in[4]);
    if (f.header.totalChunks < kGeckoMinFragmentChunks ||
        f.header.totalChunks > kGeckoMaxFragmentChunks) {
        throw Error("gecko frame invalid");
    }
    if (f.header.chunkIdx >= f.header.totalChunks) {
        throw Error("gecko frame invalid");
    }
    const size_t consumed = static_cast<size_t>(kGeckoHeaderSize) + f.header.padLen;
    if (consumed > len) {
        throw Error("gecko frame truncated");
    }
    f.payload = in + consumed;
    f.payloadLen = len - consumed;
    return f;
}

// --- GeckoPacketConn ---

GeckoPacketConn::GeckoPacketConn(std::shared_ptr<IPacketConn> inner, int minPkt,
                                 int maxPkt)
    : inner_(std::move(inner)),
      minPkt_(minPkt),
      maxPkt_(maxPkt),
      readBuf_(kGeckoBufferSize) {
    gcThread_ = std::thread([this] { GcLoop(); });
}

GeckoPacketConn::~GeckoPacketConn() {
    {
        std::lock_guard<std::mutex> lk(closeMu_);
        stop_ = true;
    }
    closeCv_.notify_all();
    if (gcThread_.joinable()) {
        gcThread_.join();
    }
}

std::shared_ptr<IPacketConn> WrapPacketConnGecko(std::shared_ptr<IPacketConn> conn,
                                                 const GeckoOptions& opts) {
    if (opts.password.empty()) {
        throw Error("gecko: password is required");
    }
    int minPkt = opts.minPacketSize != 0 ? opts.minPacketSize : kGeckoDefaultMinPacket;
    int maxPkt = opts.maxPacketSize != 0 ? opts.maxPacketSize : kGeckoDefaultMaxPacket;
    if (minPkt <= 0 || minPkt > maxPkt ||
        maxPkt > static_cast<int>(kGeckoBufferSize)) {
        throw Error("gecko: invalid min/max packet size");
    }
    auto inner = WrapPacketConnSalamander(std::move(conn), opts.password);
    return std::make_shared<GeckoPacketConn>(std::move(inner), minPkt, maxPkt);
}

// --- Send path ---

void GeckoPacketConn::WriteTo(const uint8_t* data, size_t len, const std::string& addr) {
    if (len == 0) {
        return;
    }
    if ((data[0] & 0x80) != 0) {
        // QUIC long header, do fragmentation.
        WriteFragmented(data, len, addr);
        return;
    }
    // QUIC short header (data), pass through.
    if (!inner_) {
        throw Error("gecko: no inner conn");
    }
    inner_->WriteTo(data, len, addr);
}

void GeckoPacketConn::WriteFragmented(const uint8_t* p, size_t plen,
                                      const std::string& addr) {
    const int chunks = RandomFragmentChunks();
    const size_t chunkSize = plen / static_cast<size_t>(chunks);
    const auto msgID = static_cast<uint8_t>(
        msgID_.fetch_add(1, std::memory_order_relaxed) & 0xffu);
    for (int i = 0; i < chunks; i++) {
        const size_t start = static_cast<size_t>(i) * chunkSize;
        size_t end = plen;
        if (i < chunks - 1) {
            end = start + chunkSize;
        }
        const size_t chunkLen = end - start;
        const uint16_t padLen = RandomPadLen(chunkLen);
        FrameHeader h{padLen, msgID, static_cast<uint8_t>(i),
                      static_cast<uint8_t>(chunks)};
        std::vector<uint8_t> buf(static_cast<size_t>(kGeckoHeaderSize) + padLen +
                                 chunkLen);
        const size_t n = EncodeFrame(h, p + start, chunkLen, buf.data(), buf.size());
        if (!inner_) {
            throw Error("gecko: no inner conn");
        }
        inner_->WriteTo(buf.data(), n, addr);
    }
}

// randomPadLen picks padding so the final UDP datagram (Salamander salt +
// header + padding + chunk) falls within [minPkt, maxPkt]. If the chunk alone
// already exceeds maxPkt, no padding is added.
uint16_t GeckoPacketConn::RandomPadLen(size_t chunkLen) {
    const int base = kSmSaltLen + kGeckoHeaderSize + static_cast<int>(chunkLen);
    const int lo = minPkt_ > base ? minPkt_ : base;
    if (lo > maxPkt_) {
        return 0;
    }
    return static_cast<uint16_t>(lo - base + RandIntn(maxPkt_ - lo + 1));
}

// --- Receive path ---

size_t GeckoPacketConn::ReadFrom(uint8_t* buf, size_t len, std::string& addrOut) {
    if (!inner_) {
        throw Error("gecko: no inner conn");
    }
    std::lock_guard<std::mutex> rlk(readMu_);
    for (;;) {
        std::string addr;
        const size_t n = inner_->ReadFrom(readBuf_.data(), readBuf_.size(), addr);
        if (n == 0) {
            continue;
        }
        // Top bit set -> Gecko fragment frame; clear -> short-header packet
        // or garbage, passed through for QUIC to handle.
        if ((readBuf_[0] & kGeckoFlagFragment) == 0) {
            const size_t cp = n < len ? n : len;
            std::memcpy(buf, readBuf_.data(), cp);
            addrOut = std::move(addr);
            return cp;
        }
        DecodedFrame f;
        try {
            f = DecodeFrame(readBuf_.data(), n);
        } catch (const Error&) {
            // Malformed frame; drop silently.
            continue;
        }
        std::optional<std::vector<uint8_t>> out =
            AcceptChunk(addr, f.header, f.payload, f.payloadLen);
        if (!out) {
            continue;
        }
        const size_t cp2 = out->size() < len ? out->size() : len;
        std::memcpy(buf, out->data(), cp2);
        addrOut = std::move(addr);
        return cp2;
    }
}

std::optional<std::vector<uint8_t>> GeckoPacketConn::AcceptChunk(
    const std::string& addrStr, const FrameHeader& h, const uint8_t* payload,
    size_t payloadLen) {
    const ReassemblyKey key{addrStr, h.msgID};

    std::lock_guard<std::mutex> lk(mu_);

    auto it = reassembly_.find(key);
    if (it == reassembly_.end()) {
        // Per-source cap.
        int& srcCount = perSource_[addrStr];
        if (srcCount >= static_cast<int>(kGeckoMaxPerSource)) {
            return std::nullopt;
        }
        // Global cap with eviction.
        if (reassembly_.size() >= kGeckoMaxReassembly) {
            EvictOldestLocked();
        }
        ReassemblyEntry e;
        e.chunks.resize(h.totalChunks);
        e.total = h.totalChunks;
        e.deadline = MonoTime::Now().Add(kGeckoReassemblyTTL.ns);
        it = reassembly_.emplace(key, std::move(e)).first;
        srcCount++;
    } else if (it->second.total != h.totalChunks) {
        // Inconsistent chunk count; drop.
        return std::nullopt;
    }
    ReassemblyEntry& e = it->second;
    if (static_cast<size_t>(h.chunkIdx) >= e.chunks.size() ||
        e.chunks[h.chunkIdx].has_value()) {
        // Bad index or duplicate; drop.
        return std::nullopt;
    }
    e.chunks[h.chunkIdx].emplace(payload, payload + payloadLen);
    e.received++;
    if (e.received < static_cast<size_t>(e.total)) {
        return std::nullopt;
    }

    std::vector<uint8_t> out;
    for (const auto& c : e.chunks) {
        if (c) {
            out.insert(out.end(), c->begin(), c->end());
        }
    }
    DropEntryLocked(key);
    return out;
}

// --- Maintenance ---

void GeckoPacketConn::GcLoop() {
    const std::chrono::nanoseconds interval(kGeckoReassemblyTTL.ns / 2);
    std::unique_lock<std::mutex> lk(closeMu_);
    while (!stop_) {
        closeCv_.wait_for(lk, interval);
        if (stop_) {
            break;
        }
        lk.unlock();
        GcExpired(MonoTime::Now());
        lk.lock();
    }
}

void GeckoPacketConn::GcExpired(MonoTime now) {
    std::vector<ReassemblyKey> expired;
    {
        std::lock_guard<std::mutex> lk(mu_);
        for (const auto& kv : reassembly_) {
            if (now > kv.second.deadline) {
                expired.push_back(kv.first);
            }
        }
        for (const auto& k : expired) {
            DropEntryLocked(k);
        }
    }
}

void GeckoPacketConn::DropEntryLocked(const ReassemblyKey& k) {
    auto it = reassembly_.find(k);
    if (it == reassembly_.end()) {
        return;
    }
    reassembly_.erase(it);
    auto pit = perSource_.find(k.addr);
    if (pit != perSource_.end()) {
        pit->second--;
        if (pit->second <= 0) {
            perSource_.erase(pit);
        }
    }
}

void GeckoPacketConn::EvictOldestLocked() {
    bool found = false;
    ReassemblyKey oldestKey;
    MonoTime oldestDeadline{};
    for (const auto& kv : reassembly_) {
        if (!found || kv.second.deadline < oldestDeadline) {
            oldestKey = kv.first;
            oldestDeadline = kv.second.deadline;
            found = true;
        }
    }
    if (found) {
        DropEntryLocked(oldestKey);
    }
}

// --- IPacketConn boilerplate ---

void GeckoPacketConn::Close() {
    std::call_once(closeOnce_, [this] {
        {
            std::lock_guard<std::mutex> lk(closeMu_);
            stop_ = true;
        }
        closeCv_.notify_all();
    });
    if (inner_) {
        inner_->Close();
    }
}

std::string GeckoPacketConn::LocalAddr() const { return inner_ ? inner_->LocalAddr() : ""; }

} // namespace hy2::obfs
