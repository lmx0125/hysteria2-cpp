// bandwidth_sampler.hpp - rewrite of
// core/internal/congestion/bbr/bandwidth_sampler.go.
//
// BandwidthSampler keeps track of sent and acknowledged packets and outputs a
// bandwidth sample for every packet acknowledged. The samples are taken for
// individual packets, and are not filtered; the consumer has to filter the
// bandwidth samples itself.
#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "hy2/common.hpp"
#include "hy2/congestion.hpp"
#include "hy2/bbr/bandwidth.hpp"
#include "hy2/bbr/packet_number_indexed_queue.hpp"
#include "hy2/bbr/windowed_filter.hpp"

namespace hy2::bbr {

using RoundTripCount = std::uint64_t;

constexpr Duration kInfRTT{(std::numeric_limits<std::int64_t>::max)()}; // time.Duration(math.MaxInt64)

constexpr std::size_t kDefaultConnectionStateMapQueueSize = 256;
constexpr std::size_t kDefaultCandidatesBufferSize = 256;

// SendTimeState is a subset of ConnectionStateOnSentPacket which is returned to
// the caller when the packet is acked or lost.
struct SendTimeState {
    // Whether other states in this object are valid.
    bool IsValid = false;
    // Whether the sender is app limited at the time the packet was sent.
    bool IsAppLimited = false;
    // Total number of sent bytes at the time the packet was sent (includes the
    // packet itself).
    ByteCount TotalBytesSent = 0;
    ByteCount TotalBytesAcked = 0;
    ByteCount TotalBytesLost = 0;
    // Total number of inflight bytes at the time the packet was sent (includes
    // the packet itself).
    ByteCount BytesInFlight = 0;
};

struct ExtraAckedEvent {
    // The excess bytes acknowledged in the time delta for this event.
    ByteCount ExtraAcked = 0;
    // The bytes acknowledged and time delta of the event.
    ByteCount BytesAcked = 0;
    Duration TimeDelta{};
    // The round trip of the event.
    RoundTripCount Round = 0;
};

int MaxExtraAckedEventFunc(const ExtraAckedEvent& a, const ExtraAckedEvent& b);

struct BandwidthSample {
    // The bandwidth at that particular sample. Zero if no valid sample is
    // available. (Go field: bandwidth Bandwidth.)
    Bandwidth BandwidthBps = 0;
    // The RTT measurement at this particular sample. Zero if no RTT sample is
    // available. Does not correct for delayed ack time.
    Duration Rtt{};
    // |sendRate| is computed from the current packet being acked ('P') and an
    // earlier packet that is acked before P was sent.
    Bandwidth SendRate = kInfBandwidth;
    // States captured when the packet was sent.
    SendTimeState StateAtSend;
};

// AckPoint represents a point on the ack line.
struct AckPoint {
    MonoTime AckTime{};
    ByteCount TotalBytesAcked = 0;
};

// RecentAckPoints maintains the most recent 2 ack points at distinct times.
class RecentAckPoints {
public:
    void Update(MonoTime ackTime, ByteCount totalBytesAcked);
    void Clear();
    AckPoint MostRecentPoint() const { return ackPoints_[1]; }
    AckPoint LessRecentPoint() const {
        return ackPoints_[0].TotalBytesAcked != 0 ? ackPoints_[0] : ackPoints_[1];
    }

private:
    AckPoint ackPoints_[2]{};
};

// MaxAckHeightTracker is part of the BandwidthSampler. It is called after every
// ack event to keep track of the degree of ack aggregation (a.k.a "ack height").
class MaxAckHeightTracker {
public:
    explicit MaxAckHeightTracker(RoundTripCount windowLength);

    ByteCount Get() const { return maxAckHeightFilter_.GetBest().ExtraAcked; }

    ByteCount Update(Bandwidth bandwidthEstimate, bool isNewMaxBandwidth,
                     RoundTripCount roundTripCount, PacketNumber lastSentPacketNumber,
                     PacketNumber lastAckedPacketNumber, MonoTime ackTime,
                     ByteCount bytesAcked);

    void SetFilterWindowLength(RoundTripCount length) { maxAckHeightFilter_.SetWindowLength(length); }
    void Reset(ByteCount newHeight, RoundTripCount newTime);
    void SetAckAggregationBandwidthThreshold(double threshold) { ackAggregationBandwidthThreshold_ = threshold; }
    void SetStartNewAggregationEpochAfterFullRound(bool value) { startNewAggregationEpochAfterFullRound_ = value; }
    void SetReduceExtraAckedOnBandwidthIncrease(bool value) { reduceExtraAckedOnBandwidthIncrease_ = value; }

    double AckAggregationBandwidthThreshold() const { return ackAggregationBandwidthThreshold_; }
    std::uint64_t NumAckAggregationEpochs() const { return numAckAggregationEpochs_; }
    bool ReduceExtraAckedOnBandwidthIncrease() const { return reduceExtraAckedOnBandwidthIncrease_; }

private:
    WindowedFilter<ExtraAckedEvent, RoundTripCount> maxAckHeightFilter_;
    // The time this aggregation started and the number of bytes acked during it.
    MonoTime aggregationEpochStartTime_{};
    ByteCount aggregationEpochBytes_ = 0;
    // The last sent packet number before the current aggregation epoch started.
    PacketNumber lastSentPacketNumberBeforeEpoch_ = kInvalidPacketNumber;
    // The number of ack aggregation epochs ever started, including the ongoing
    // one. Stats only.
    std::uint64_t numAckAggregationEpochs_ = 0;
    double ackAggregationBandwidthThreshold_ = 1.0;
    bool startNewAggregationEpochAfterFullRound_ = false;
    bool reduceExtraAckedOnBandwidthIncrease_ = false;
};

class BandwidthSampler;

// ConnectionStateOnSentPacket represents the information about a sent packet
// and the state of the connection at the moment the packet was sent,
// specifically the information about the most recently acknowledged packet at
// that moment.
struct ConnectionStateOnSentPacket {
    // Time at which the packet is sent.
    MonoTime SentTime{};
    // Size of the packet.
    ByteCount Size = 0;
    // The value of |TotalBytesSentAtLastAckedPacket| at the time the packet
    // was sent.
    ByteCount TotalBytesSentAtLastAckedPacket = 0;
    // The value of |LastAckedPacketSentTime| at the time the packet was sent.
    MonoTime LastAckedPacketSentTime{};
    // The value of |LastAckedPacketAckTime| at the time the packet was sent.
    MonoTime LastAckedPacketAckTime{};
    // Send time states that are returned to the congestion controller when the
    // packet is acked or lost.
    SendTimeState state;

    ConnectionStateOnSentPacket() = default;

    // Snapshot constructor. Records the current state of the sampler.
    // |bytesInFlight| is the bytes in flight right after the packet is sent.
    ConnectionStateOnSentPacket(MonoTime sentTime, ByteCount size, ByteCount bytesInFlight,
                                const BandwidthSampler& sampler);
};

// hy2's shared cc::AckedPacketInfo / LostPacketInfo do not carry byte counts
// (unlike quic-go's originals), so the sender converts them into these
// internal types (recovering byte counts from its own send records) before
// feeding the sampler.
struct SamplerAckedPacket {
    PacketNumber packetNumber = 0;
    ByteCount BytesAcked = 0;
};

struct SamplerLostPacket {
    PacketNumber packetNumber = 0;
    ByteCount BytesLost = 0;
};

struct CongestionEventSample {
    // The maximum bandwidth sample from all acked packets. Zero if no samples
    // are available.
    Bandwidth SampleMaxBandwidth = 0;
    // Whether |SampleMaxBandwidth| is from an app-limited sample.
    bool SampleIsAppLimited = false;
    // The minimum rtt sample from all acked packets. kInfRTT if no samples are
    // available.
    Duration SampleRtt = kInfRTT;
    // For each packet p in acked packets, the max value of INFLIGHT(p), where
    // INFLIGHT(p) is the number of bytes acked while p is inflight.
    ByteCount SampleMaxInflight = 0;
    // The send state of the largest packet in ackedPackets, unless it is empty.
    // If ackedPackets is empty, it's the send state of the largest packet in
    // lostPackets.
    SendTimeState LastPacketSendState;
    // The number of extra bytes acked from this ack event, compared to what is
    // expected from the flow's bandwidth. Larger value means more ack
    // aggregation.
    ByteCount ExtraAcked = 0;
};

class BandwidthSampler {
public:
    explicit BandwidthSampler(RoundTripCount maxAckHeightTrackerWindowLength);

    ByteCount MaxAckHeight() const { return maxAckHeightTracker_.Get(); }
    std::uint64_t NumAckAggregationEpochs() const { return maxAckHeightTracker_.NumAckAggregationEpochs(); }
    void SetMaxAckHeightTrackerWindowLength(RoundTripCount length) {
        maxAckHeightTracker_.SetFilterWindowLength(length);
    }
    void ResetMaxAckHeightTracker(ByteCount newHeight, RoundTripCount newTime) {
        maxAckHeightTracker_.Reset(newHeight, newTime);
    }
    void SetStartNewAggregationEpochAfterFullRound(bool value) {
        maxAckHeightTracker_.SetStartNewAggregationEpochAfterFullRound(value);
    }
    void SetLimitMaxAckHeightTrackerBySendRate(bool value) { limitMaxAckHeightTrackerBySendRate_ = value; }
    void SetReduceExtraAckedOnBandwidthIncrease(bool value) {
        maxAckHeightTracker_.SetReduceExtraAckedOnBandwidthIncrease(value);
    }
    void EnableOverestimateAvoidance();
    bool IsOverestimateAvoidanceEnabled() const { return overestimateAvoidance_; }

    // Exposes the ack height tracker (mirrors Go's package-private field
    // access in tests).
    const MaxAckHeightTracker& maxAckHeightTracker() const { return maxAckHeightTracker_; }

    void OnPacketSent(MonoTime sentTime, PacketNumber packetNumber, ByteCount bytes,
                      ByteCount bytesInFlight, bool isRetransmittable);

    CongestionEventSample OnCongestionEvent(
        MonoTime ackTime, const std::vector<SamplerAckedPacket>& ackedPackets,
        const std::vector<SamplerLostPacket>& lostPackets, Bandwidth maxBandwidth,
        Bandwidth estBandwidthUpperBound, RoundTripCount roundTripCount);

    SendTimeState OnPacketLost(PacketNumber packetNumber, ByteCount bytesLost);

    void OnPacketNeutered(PacketNumber packetNumber);

    void OnAppLimited();

    void RemoveObsoletePackets(PacketNumber leastUnacked);

    ByteCount TotalBytesSent() const { return totalBytesSent_; }
    ByteCount TotalBytesLost() const { return totalBytesLost_; }
    ByteCount TotalBytesAcked() const { return totalBytesAcked_; }
    ByteCount TotalBytesNeutered() const { return totalBytesNeutered_; }
    bool IsAppLimited() const { return isAppLimited_; }
    PacketNumber EndOfAppLimitedPhase() const { return endOfAppLimitedPhase_; }

    // Size recorded for a previously sent packet, or 0 if not tracked.
    ByteCount TrackedPacketSize(PacketNumber packetNumber) const;

private:
    friend ConnectionStateOnSentPacket::ConnectionStateOnSentPacket(
        MonoTime sentTime, ByteCount size, ByteCount bytesInFlight,
        const BandwidthSampler& sampler);

    bool ChooseA0Point(ByteCount totalBytesAcked, AckPoint& a0);

    BandwidthSample OnPacketAcknowledged(MonoTime ackTime, PacketNumber packetNumber);

    ByteCount OnAckEventEnd(Bandwidth bandwidthEstimate, bool isNewMaxBandwidth,
                            RoundTripCount roundTripCount);

    // The total number of congestion controlled bytes sent during the
    // connection.
    ByteCount totalBytesSent_ = 0;
    // The total number of congestion controlled bytes which were acknowledged.
    ByteCount totalBytesAcked_ = 0;
    // The total number of congestion controlled bytes which were lost.
    ByteCount totalBytesLost_ = 0;
    // The total number of congestion controlled bytes which have been neutered.
    ByteCount totalBytesNeutered_ = 0;

    // The value of |totalBytesSent_| at the time the last acknowledged packet
    // was sent. Valid only when |lastAckedPacketSentTime_| is valid.
    ByteCount totalBytesSentAtLastAckedPacket_ = 0;

    // The time at which the last acknowledged packet was sent. Zero if no valid
    // timestamp is available.
    MonoTime lastAckedPacketSentTime_{};
    // The time at which the most recent packet was acknowledged.
    MonoTime lastAckedPacketAckTime_{};

    // The most recently sent packet.
    PacketNumber lastSentPacket_ = kInvalidPacketNumber;
    // The most recently acked packet.
    PacketNumber lastAckedPacket_ = kInvalidPacketNumber;

    // Indicates whether the sampler is currently in an app-limited phase.
    bool isAppLimited_ = false;

    // The packet that will be acknowledged after this one will cause the
    // sampler to exit the app-limited phase.
    PacketNumber endOfAppLimitedPhase_ = kInvalidPacketNumber;

    // Record of the connection state at the point where each packet in flight
    // was sent, indexed by the packet number.
    PacketNumberIndexedQueue<ConnectionStateOnSentPacket> connectionStateMap_;

    RecentAckPoints recentAckPoints_;
    RingBuffer<AckPoint> a0Candidates_;

    // Maximum number of tracked packets.
    ByteCount maxTrackedPackets_ = 0;

    MaxAckHeightTracker maxAckHeightTracker_;
    ByteCount totalBytesAckedAfterLastAckEvent_ = 0;

    // True if connection option 'BSAO' is set.
    bool overestimateAvoidance_ = false;

    // True if connection option 'BBRB' is set.
    bool limitMaxAckHeightTrackerBySendRate_ = false;
};

void SentPacketToSendTimeState(const ConnectionStateOnSentPacket& sentPacket,
                               SendTimeState& sendTimeState);

// BytesFromBandwidthAndTimeDelta calculates bytes from a bandwidth (bits per
// second) and a time delta.
inline ByteCount BytesFromBandwidthAndTimeDelta(Bandwidth bandwidth, Duration delta) {
    // Multiplication wraps modulo 2^64 exactly like in Go; the division stays
    // signed to match Go's truncation semantics.
    std::int64_t product = static_cast<std::int64_t>(
        static_cast<std::uint64_t>(bandwidth) * static_cast<std::uint64_t>(delta.ns));
    return product / (kSecondNanos * 8);
}

inline Duration TimeDeltaFromBytesAndBandwidth(ByteCount bytes, Bandwidth bandwidth) {
    std::int64_t num = static_cast<std::int64_t>(static_cast<std::uint64_t>(bytes) * 8ULL *
                                                 static_cast<std::uint64_t>(kSecondNanos));
    return Duration(num / static_cast<std::int64_t>(bandwidth));
}

} // namespace hy2::bbr
