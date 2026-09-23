// frag.cpp - rewrite of core/internal/frag/frag.go
#include "hy2/frag.hpp"

namespace hy2::frag {

std::vector<proto::UDPMessage> FragUDPMessage(const proto::UDPMessage& m, size_t maxSize) {
    if (m.Size() <= maxSize) {
        return {m};
    }
    const auto& fullPayload = m.Data;
    if (m.HeaderSize() >= maxSize) {
        return {};
    }
    size_t maxPayloadSize = maxSize - m.HeaderSize();
    size_t off = 0;
    uint8_t fragID = 0;
    uint8_t fragCount = static_cast<uint8_t>((fullPayload.size() + maxPayloadSize - 1) / maxPayloadSize);
    std::vector<proto::UDPMessage> frags;
    frags.reserve(fragCount);
    while (off < fullPayload.size()) {
        size_t payloadSize = fullPayload.size() - off;
        if (payloadSize > maxPayloadSize) {
            payloadSize = maxPayloadSize;
        }
        proto::UDPMessage f;
        f.SessionID = m.SessionID;
        f.PacketID = m.PacketID;
        f.Addr = m.Addr;
        f.FragID = fragID;
        f.FragCount = fragCount;
        f.Data.assign(fullPayload.begin() + static_cast<long>(off),
                      fullPayload.begin() + static_cast<long>(off + payloadSize));
        frags.push_back(std::move(f));
        off += payloadSize;
        fragID++;
    }
    return frags;
}

std::shared_ptr<proto::UDPMessage> Defragger::Feed(std::shared_ptr<proto::UDPMessage> m) {
    if (!m) return nullptr;
    if (m->FragCount <= 1) {
        // Common case (no fragmentation): pass the caller's object through
        // untouched. Used to copy the whole message here.
        return m;
    }
    if (m->FragID >= m->FragCount) {
        return nullptr;
    }
    if (m->PacketID != pktID_ || frags_.size() != m->FragCount) {
        // new message, clear previous state
        pktID_ = m->PacketID;
        size_ = m->Data.size();
        frags_.assign(m->FragCount, nullptr);
        frags_[m->FragID] = std::move(m);
        count_ = 1;
    } else if (!frags_[m->FragID]) {
        size_ += m->Data.size();
        frags_[m->FragID] = std::move(m);
        count_++;
        if (count_ == frags_.size()) {
            // all fragments received, assemble into a new message
            auto assembled = std::make_shared<proto::UDPMessage>();
            assembled->SessionID = frags_[0]->SessionID;
            assembled->PacketID = frags_[0]->PacketID;
            assembled->Addr = frags_[0]->Addr;
            assembled->FragID = 0;
            assembled->FragCount = 1;
            // Reserve exact capacity to avoid reallocation
            assembled->Data.reserve(size_);
            for (const auto& f : frags_) {
                assembled->Data.insert(assembled->Data.end(),
                                       f->Data.begin(), f->Data.end());
            }
            frags_.clear();
            count_ = 0;
            size_ = 0;
            return assembled;
        }
    }
    return nullptr;
}

} // namespace hy2::frag
