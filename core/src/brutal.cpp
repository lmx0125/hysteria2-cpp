// brutal.cpp - rewrite of core/internal/congestion/brutal/brutal.go
#include "hy2/brutal.hpp"

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <string>

namespace hy2::cc {

namespace {

bool envDebugEnabled() {
    const char* v = std::getenv("HYSTERIA_BRUTAL_DEBUG");
    if (!v || !*v) return false;
    std::string s(v);
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return !(s == "0" || s == "false" || s == "no" || s == "off");
}

std::string hhmmssNow() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

} // namespace

BrutalSender::BrutalSender(uint64_t bps, bool disableLossCompensation)
    : bps_(static_cast<ByteCount>(bps)),
      maxDatagramSize_(kInitialPacketSize),
      pacer_(Pacer::BandwidthFunc([this]() -> ByteCount {
          return static_cast<ByteCount>(static_cast<double>(bps_) / ackRate_);
      })),
      ackRate_(1.0),
      disableLossCompensation_(disableLossCompensation),
      debug_(envDebugEnabled()) {}

MonoTime BrutalSender::TimeUntilSend(ByteCount bytesInFlight) {
    (void)bytesInFlight;
    return pacer_.TimeUntilSend();
}

bool BrutalSender::HasPacingBudget(MonoTime now) {
    return pacer_.Budget(now) >= maxDatagramSize_;
}

bool BrutalSender::CanSend(ByteCount bytesInFlight) {
    return bytesInFlight <= GetCongestionWindow();
}

ByteCount BrutalSender::GetCongestionWindow() {
    Duration rtt = rttStats_ ? rttStats_->SmoothedRTT() : Duration(0);
    if (rtt.ns <= 0) {
        return 10240;
    }
    ByteCount cwnd = static_cast<ByteCount>(
        static_cast<double>(bps_) * rtt.Seconds() * kCongestionWindowMultiplier / ackRate_);
    if (cwnd < maxDatagramSize_) {
        cwnd = maxDatagramSize_;
    }
    return cwnd;
}

void BrutalSender::OnPacketSent(MonoTime sentTime, ByteCount /*bytesInFlight*/,
                                PacketNumber /*packetNumber*/, ByteCount bytes,
                                bool /*isRetransmittable*/) {
    pacer_.SentPacket(sentTime, bytes);
}

void BrutalSender::OnPacketAcked(PacketNumber /*number*/, ByteCount /*ackedBytes*/,
                                 ByteCount /*priorInFlight*/, MonoTime /*eventTime*/) {
    // Stub
}

void BrutalSender::OnCongestionEvent(PacketNumber /*number*/, ByteCount /*lostBytes*/,
                                     ByteCount /*priorInFlight*/) {
    // Stub
}

void BrutalSender::OnCongestionEventEx(ByteCount /*priorInFlight*/, MonoTime eventTime,
                                       const std::vector<AckedPacketInfo>& ackedPackets,
                                       const std::vector<LostPacketInfo>& lostPackets) {
    int64_t currentTimestamp = eventTime.ns / 1000000000LL; // whole seconds
    size_t slot = static_cast<size_t>(currentTimestamp % kPktInfoSlotCount);
    if (pktInfoSlots_[slot].Timestamp == currentTimestamp) {
        pktInfoSlots_[slot].LossCount += static_cast<uint64_t>(lostPackets.size());
        pktInfoSlots_[slot].AckCount += static_cast<uint64_t>(ackedPackets.size());
    } else {
        // uninitialized slot or too old, reset
        pktInfoSlots_[slot].Timestamp = currentTimestamp;
        pktInfoSlots_[slot].AckCount = static_cast<uint64_t>(ackedPackets.size());
        pktInfoSlots_[slot].LossCount = static_cast<uint64_t>(lostPackets.size());
    }
    updateAckRate(currentTimestamp);
}

void BrutalSender::SetMaxDatagramSize(ByteCount size) {
    maxDatagramSize_ = size;
    pacer_.SetMaxDatagramSize(size);
}

void BrutalSender::updateAckRate(int64_t currentTimestamp) {
    if (disableLossCompensation_) {
        ackRate_ = 1;
        return;
    }
    int64_t minTimestamp = currentTimestamp - kPktInfoSlotCount;
    uint64_t ackCount = 0, lossCount = 0;
    for (const auto& info : pktInfoSlots_) {
        if (info.Timestamp < minTimestamp) {
            continue;
        }
        ackCount += info.AckCount;
        lossCount += info.LossCount;
    }
    if (ackCount + lossCount < kMinSampleCount) {
        ackRate_ = 1;
        if (canPrintAckRate(currentTimestamp)) {
            lastAckPrintTimestamp_ = currentTimestamp;
            char buf[160];
            Duration rtt = rttStats_ ? rttStats_->SmoothedRTT() : Duration(0);
            std::snprintf(buf, sizeof(buf),
                          "Not enough samples (total=%llu, ack=%llu, loss=%llu, rtt=%lld)",
                          static_cast<unsigned long long>(ackCount + lossCount),
                          static_cast<unsigned long long>(ackCount),
                          static_cast<unsigned long long>(lossCount),
                          rtt.Milliseconds());
            debugPrint(buf);
        }
        return;
    }
    double rate = static_cast<double>(ackCount) / static_cast<double>(ackCount + lossCount);
    if (rate < kMinAckRate) {
        ackRate_ = kMinAckRate;
        if (canPrintAckRate(currentTimestamp)) {
            lastAckPrintTimestamp_ = currentTimestamp;
            char buf[192];
            Duration rtt = rttStats_ ? rttStats_->SmoothedRTT() : Duration(0);
            std::snprintf(buf, sizeof(buf),
                          "ACK rate too low: %.2f, clamped to %.2f (total=%llu, ack=%llu, loss=%llu, rtt=%lld)",
                          rate, kMinAckRate,
                          static_cast<unsigned long long>(ackCount + lossCount),
                          static_cast<unsigned long long>(ackCount),
                          static_cast<unsigned long long>(lossCount),
                          rtt.Milliseconds());
            debugPrint(buf);
        }
        return;
    }
    ackRate_ = rate;
    if (canPrintAckRate(currentTimestamp)) {
        lastAckPrintTimestamp_ = currentTimestamp;
        char buf[160];
        Duration rtt = rttStats_ ? rttStats_->SmoothedRTT() : Duration(0);
        std::snprintf(buf, sizeof(buf),
                      "ACK rate: %.2f (total=%llu, ack=%llu, loss=%llu, rtt=%lld)",
                      rate,
                      static_cast<unsigned long long>(ackCount + lossCount),
                      static_cast<unsigned long long>(ackCount),
                      static_cast<unsigned long long>(lossCount),
                      rtt.Milliseconds());
        debugPrint(buf);
    }
}

bool BrutalSender::canPrintAckRate(int64_t currentTimestamp) const {
    return debug_ && currentTimestamp - lastAckPrintTimestamp_ >= 2;
}

void BrutalSender::debugPrint(const std::string& s) const {
    std::printf("[BrutalSender] [%s] %s\n", hhmmssNow().c_str(), s.c_str());
}

} // namespace hy2::cc
