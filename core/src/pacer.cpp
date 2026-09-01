// pacer.cpp - rewrite of core/internal/congestion/common/pacer.go
#include "hy2/pacer.hpp"

#include <algorithm>
#include <cstdint>

namespace hy2::cc {

Pacer::Pacer(BandwidthFunc getBandwidth)
    : budgetAtLastSent_(0),
      maxDatagramSize_(kInitialPacketSize),
      getBandwidth_(std::move(getBandwidth)) {
    // Mirrors Go NewPacer: the initial budget is the dynamic max burst size,
    // not a fixed value - high-bandwidth connections get a proportionally
    // larger initial burst (max(4ms * bw, 10 * maxDatagramSize)).
    budgetAtLastSent_ = maxBurstSize();
}

void Pacer::SentPacket(MonoTime sendTime, ByteCount size) {
    ByteCount budget = Budget(sendTime);
    if (size > budget) {
        budgetAtLastSent_ = 0;
    } else {
        budgetAtLastSent_ = budget - size;
    }
    lastSentTime_ = sendTime;
    hasLastSentTime_ = true;
}

ByteCount Pacer::Budget(MonoTime now) {
    if (!hasLastSentTime_) {
        return maxBurstSize();
    }
    ByteCount bw = getBandwidth_();
    int64_t elapsedNs = now.Sub(lastSentTime_);
    if (elapsedNs < 0) elapsedNs = 0;
    // Mirrors Go: budgetAtLastSent + bw*elapsedNs/1e9. Values stay well within
    // int64 range for realistic bandwidths/durations.
    ByteCount budget = budgetAtLastSent_;
    if (bw > 0) { // defensive: a zero bandwidth never refills the budget
        budget += bw * elapsedNs / 1000000000LL;
    }
    if (budget < 0) { // protect against overflows
        budget = (static_cast<ByteCount>(1) << 62) - 1;
    }
    return std::min(maxBurstSize(), budget);
}

ByteCount Pacer::maxBurstSize() {
    ByteCount bw = getBandwidth_();
    ByteCount byDelay = 0;
    if (bw > 0) { // defensive: Go would divide by zero here
        byDelay = static_cast<ByteCount>(
                      static_cast<int64_t>(kMaxBurstPacingDelayMultiplier) * kMinPacingDelay.ns) *
                  bw / 1000000000LL;
    }
    return std::max(byDelay, kMaxBurstPackets * maxDatagramSize_);
}

MonoTime Pacer::TimeUntilSend() {
    if (budgetAtLastSent_ >= maxDatagramSize_) {
        return MonoTime(0);
    }
    ByteCount bw = getBandwidth_();
    if (bw <= 0) {
        // Defensive: with zero bandwidth the budget can never refill.
        // Deviation from Go (which would panic on division by zero): report
        // a distant deadline instead of crashing.
        return lastSentTime_.Add(Duration::FromSeconds(3600).ns);
    }
    uint64_t diff = static_cast<uint64_t>(maxDatagramSize_ - budgetAtLastSent_) * 1000000000ULL;
    uint64_t bwu = static_cast<uint64_t>(bw);
    // We might need to round up this value.
    // Otherwise, we might have a budget (slightly) smaller than the datagram size when the timer expires.
    uint64_t d = diff / bwu;
    // this is effectively a math.Ceil, but using only integer math
    if (diff % bwu > 0) {
        d++;
    }
    int64_t delayNs = static_cast<int64_t>(d);
    if (delayNs < kMinPacingDelay.ns) {
        delayNs = kMinPacingDelay.ns;
    }
    return lastSentTime_.Add(delayNs);
}

void Pacer::SetMaxDatagramSize(ByteCount s) {
    maxDatagramSize_ = s;
}

} // namespace hy2::cc
