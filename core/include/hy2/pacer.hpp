// pacer.hpp - Token bucket pacing. Rewrite of core/internal/congestion/common/pacer.go.
#pragma once

#include <functional>

#include "hy2/common.hpp"
#include "hy2/congestion.hpp"

namespace hy2::cc {

constexpr int kMaxBurstPackets = 10;
constexpr int kMaxBurstPacingDelayMultiplier = 4;

// Pacer implements a token bucket pacing algorithm.
class Pacer {
public:
    using BandwidthFunc = std::function<ByteCount()>; // bytes/s

    explicit Pacer(BandwidthFunc getBandwidth);

    void SentPacket(MonoTime sendTime, ByteCount size);
    ByteCount Budget(MonoTime now);
    // TimeUntilSend returns when the next packet should be sent.
    // Returns a zero time if a packet can be sent immediately.
    MonoTime TimeUntilSend();
    void SetMaxDatagramSize(ByteCount s);

private:
    ByteCount maxBurstSize();

    ByteCount budgetAtLastSent_ = 0;
    ByteCount maxDatagramSize_ = 0;
    MonoTime lastSentTime_{};
    bool hasLastSentTime_ = false;
    BandwidthFunc getBandwidth_; // in bytes/s
};

} // namespace hy2::cc
