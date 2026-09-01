// bandwidth_sampler.cpp - rewrite of
// core/internal/congestion/bbr/bandwidth_sampler.go.
#include "hy2/bbr/bandwidth_sampler.hpp"

#include <algorithm>

namespace hy2::bbr {

int MaxExtraAckedEventFunc(const ExtraAckedEvent& a, const ExtraAckedEvent& b) {
    if (a.ExtraAcked > b.ExtraAcked) {
        return 1;
    } else if (a.ExtraAcked < b.ExtraAcked) {
        return -1;
    }
    return 0;
}

MaxAckHeightTracker::MaxAckHeightTracker(RoundTripCount windowLength)
    : maxAckHeightFilter_(windowLength, MaxExtraAckedEventFunc),
      lastSentPacketNumberBeforeEpoch_(kInvalidPacketNumber) {}

ByteCount MaxAckHeightTracker::Update(Bandwidth bandwidthEstimate, bool isNewMaxBandwidth,
                                      RoundTripCount roundTripCount,
                                      PacketNumber lastSentPacketNumber,
                                      PacketNumber lastAckedPacketNumber, MonoTime ackTime,
                                      ByteCount bytesAcked) {
    bool forceNewEpoch = false;

    if (reduceExtraAckedOnBandwidthIncrease_ && isNewMaxBandwidth) {
        // Save and clear existing entries.
        ExtraAckedEvent best = maxAckHeightFilter_.GetBest();
        ExtraAckedEvent secondBest = maxAckHeightFilter_.GetSecondBest();
        ExtraAckedEvent thirdBest = maxAckHeightFilter_.GetThirdBest();
        maxAckHeightFilter_.Clear();

        // Reinsert the heights into the filter after recalculating.
        ByteCount expectedBytesAcked = BytesFromBandwidthAndTimeDelta(bandwidthEstimate, best.TimeDelta);
        if (expectedBytesAcked < best.BytesAcked) {
            best.ExtraAcked = best.BytesAcked - expectedBytesAcked;
            maxAckHeightFilter_.Update(best, best.Round);
        }
        expectedBytesAcked = BytesFromBandwidthAndTimeDelta(bandwidthEstimate, secondBest.TimeDelta);
        if (expectedBytesAcked < secondBest.BytesAcked) {
            secondBest.ExtraAcked = secondBest.BytesAcked - expectedBytesAcked;
            maxAckHeightFilter_.Update(secondBest, secondBest.Round);
        }
        expectedBytesAcked = BytesFromBandwidthAndTimeDelta(bandwidthEstimate, thirdBest.TimeDelta);
        if (expectedBytesAcked < thirdBest.BytesAcked) {
            thirdBest.ExtraAcked = thirdBest.BytesAcked - expectedBytesAcked;
            maxAckHeightFilter_.Update(thirdBest, thirdBest.Round);
        }
    }

    // If any packet sent after the start of the epoch has been acked, start a
    // new epoch.
    if (startNewAggregationEpochAfterFullRound_ &&
        lastSentPacketNumberBeforeEpoch_ != kInvalidPacketNumber &&
        lastAckedPacketNumber != kInvalidPacketNumber &&
        lastAckedPacketNumber > lastSentPacketNumberBeforeEpoch_) {
        forceNewEpoch = true;
    }
    if (aggregationEpochStartTime_.IsZero() || forceNewEpoch) {
        aggregationEpochBytes_ = bytesAcked;
        aggregationEpochStartTime_ = ackTime;
        lastSentPacketNumberBeforeEpoch_ = lastSentPacketNumber;
        numAckAggregationEpochs_++;
        return 0;
    }

    // Compute how many bytes are expected to be delivered, assuming max
    // bandwidth is correct.
    Duration aggregationDelta{ackTime.Sub(aggregationEpochStartTime_)};
    ByteCount expectedBytesAcked = BytesFromBandwidthAndTimeDelta(bandwidthEstimate, aggregationDelta);
    // Reset the current aggregation epoch as soon as the ack arrival rate is
    // less than or equal to the max bandwidth.
    if (aggregationEpochBytes_ <=
        static_cast<ByteCount>(ackAggregationBandwidthThreshold_ *
                               static_cast<double>(expectedBytesAcked))) {
        // Reset to start measuring a new aggregation epoch.
        aggregationEpochBytes_ = bytesAcked;
        aggregationEpochStartTime_ = ackTime;
        lastSentPacketNumberBeforeEpoch_ = lastSentPacketNumber;
        numAckAggregationEpochs_++;
        return 0;
    }

    aggregationEpochBytes_ += bytesAcked;

    // Compute how many extra bytes were delivered vs max bandwidth.
    ByteCount extraBytesAcked = aggregationEpochBytes_ - expectedBytesAcked;
    ExtraAckedEvent newEvent;
    newEvent.ExtraAcked = extraBytesAcked;
    newEvent.BytesAcked = aggregationEpochBytes_;
    newEvent.TimeDelta = aggregationDelta;
    maxAckHeightFilter_.Update(newEvent, roundTripCount);
    return extraBytesAcked;
}

void MaxAckHeightTracker::Reset(ByteCount newHeight, RoundTripCount newTime) {
    ExtraAckedEvent newEvent;
    newEvent.ExtraAcked = newHeight;
    newEvent.Round = newTime;
    maxAckHeightFilter_.Reset(newEvent, newTime);
}

void RecentAckPoints::Update(MonoTime ackTime, ByteCount totalBytesAcked) {
    if (ackTime < ackPoints_[1].AckTime) {
        ackPoints_[1].AckTime = ackTime;
    } else if (ackTime > ackPoints_[1].AckTime) {
        ackPoints_[0] = ackPoints_[1];
        ackPoints_[1].AckTime = ackTime;
    }

    ackPoints_[1].TotalBytesAcked = totalBytesAcked;
}

void RecentAckPoints::Clear() {
    ackPoints_[0] = AckPoint{};
    ackPoints_[1] = AckPoint{};
}

ConnectionStateOnSentPacket::ConnectionStateOnSentPacket(MonoTime sentTime, ByteCount size,
                                                         ByteCount bytesInFlight,
                                                         const BandwidthSampler& sampler)
    : SentTime(sentTime),
      Size(size),
      TotalBytesSentAtLastAckedPacket(sampler.totalBytesSentAtLastAckedPacket_),
      LastAckedPacketSentTime(sampler.lastAckedPacketSentTime_),
      LastAckedPacketAckTime(sampler.lastAckedPacketAckTime_) {
    state.IsValid = true;
    state.IsAppLimited = sampler.isAppLimited_;
    state.TotalBytesSent = sampler.totalBytesSent_;
    state.TotalBytesAcked = sampler.totalBytesAcked_;
    state.TotalBytesLost = sampler.totalBytesLost_;
    state.BytesInFlight = bytesInFlight;
}

BandwidthSampler::BandwidthSampler(RoundTripCount maxAckHeightTrackerWindowLength)
    : connectionStateMap_(kDefaultConnectionStateMapQueueSize),
      maxAckHeightTracker_(maxAckHeightTrackerWindowLength) {
    a0Candidates_.Init(kDefaultCandidatesBufferSize);
}

void BandwidthSampler::EnableOverestimateAvoidance() {
    if (overestimateAvoidance_) {
        return;
    }

    overestimateAvoidance_ = true;
    maxAckHeightTracker_.SetAckAggregationBandwidthThreshold(2.0);
}

void BandwidthSampler::OnPacketSent(MonoTime sentTime, PacketNumber packetNumber, ByteCount bytes,
                                    ByteCount bytesInFlight, bool isRetransmittable) {
    lastSentPacket_ = packetNumber;

    if (!isRetransmittable) {
        return;
    }

    totalBytesSent_ += bytes;

    // If there are no packets in flight, the time at which the new transmission
    // opens can be treated as the A_0 point for the purpose of bandwidth
    // sampling.
    if (bytesInFlight == 0) {
        lastAckedPacketAckTime_ = sentTime;
        if (overestimateAvoidance_) {
            recentAckPoints_.Clear();
            recentAckPoints_.Update(sentTime, totalBytesAcked_);
            a0Candidates_.Clear();
            a0Candidates_.PushBack(recentAckPoints_.MostRecentPoint());
        }
        totalBytesSentAtLastAckedPacket_ = totalBytesSent_;

        // In this situation ack compression is not a concern, set send rate to
        // effectively infinite.
        lastAckedPacketSentTime_ = sentTime;
    }

    ConnectionStateOnSentPacket sentPacket(sentTime, bytes, bytesInFlight + bytes, *this);
    connectionStateMap_.Emplace(packetNumber, &sentPacket);
}

CongestionEventSample BandwidthSampler::OnCongestionEvent(
    MonoTime ackTime, const std::vector<SamplerAckedPacket>& ackedPackets,
    const std::vector<SamplerLostPacket>& lostPackets, Bandwidth maxBandwidth,
    Bandwidth estBandwidthUpperBound, RoundTripCount roundTripCount) {
    CongestionEventSample eventSample;

    SendTimeState lastLostPacketSendState;

    for (const auto& p : lostPackets) {
        SendTimeState sendState = OnPacketLost(p.packetNumber, p.BytesLost);
        if (sendState.IsValid) {
            lastLostPacketSendState = sendState;
        }
    }

    if (ackedPackets.empty()) {
        // Only populate send state for a loss-only event.
        eventSample.LastPacketSendState = lastLostPacketSendState;
        return eventSample;
    }

    SendTimeState lastAckedPacketSendState;
    Bandwidth maxSendRate = 0;

    for (const auto& p : ackedPackets) {
        BandwidthSample sample = OnPacketAcknowledged(ackTime, p.packetNumber);
        if (!sample.StateAtSend.IsValid) {
            continue;
        }

        lastAckedPacketSendState = sample.StateAtSend;

        if (sample.Rtt.ns != 0 && sample.Rtt.ns < eventSample.SampleRtt.ns) {
            eventSample.SampleRtt = sample.Rtt;
        }
        if (sample.BandwidthBps > eventSample.SampleMaxBandwidth) {
            eventSample.SampleMaxBandwidth = sample.BandwidthBps;
            eventSample.SampleIsAppLimited = sample.StateAtSend.IsAppLimited;
        }
        if (sample.SendRate != kInfBandwidth && sample.SendRate > maxSendRate) {
            maxSendRate = sample.SendRate;
        }
        ByteCount inflightSample = totalBytesAcked_ - lastAckedPacketSendState.TotalBytesAcked;
        if (inflightSample > eventSample.SampleMaxInflight) {
            eventSample.SampleMaxInflight = inflightSample;
        }
    }

    if (!lastLostPacketSendState.IsValid) {
        eventSample.LastPacketSendState = lastAckedPacketSendState;
    } else if (!lastAckedPacketSendState.IsValid) {
        eventSample.LastPacketSendState = lastLostPacketSendState;
    } else {
        // If two packets are inflight and an alarm is armed to lose a packet and
        // it wakes up late, then the first of two in flight packets could have
        // been acknowledged before the wakeup, which re-evaluates loss
        // detection, and could declare the later of the two lost.
        if (lostPackets.back().packetNumber > ackedPackets.back().packetNumber) {
            eventSample.LastPacketSendState = lastLostPacketSendState;
        } else {
            eventSample.LastPacketSendState = lastAckedPacketSendState;
        }
    }

    bool isNewMaxBandwidth = eventSample.SampleMaxBandwidth > maxBandwidth;
    if (eventSample.SampleMaxBandwidth > maxBandwidth) {
        maxBandwidth = eventSample.SampleMaxBandwidth;
    }
    if (limitMaxAckHeightTrackerBySendRate_ && maxSendRate > maxBandwidth) {
        maxBandwidth = maxSendRate;
    }

    eventSample.ExtraAcked =
        OnAckEventEnd(std::min(estBandwidthUpperBound, maxBandwidth), isNewMaxBandwidth,
                      roundTripCount);

    return eventSample;
}

SendTimeState BandwidthSampler::OnPacketLost(PacketNumber packetNumber, ByteCount bytesLost) {
    SendTimeState s;
    totalBytesLost_ += bytesLost;
    const ConnectionStateOnSentPacket* sentPacketPointer = connectionStateMap_.GetEntry(packetNumber);
    if (sentPacketPointer != nullptr) {
        SentPacketToSendTimeState(*sentPacketPointer, s);
    }
    return s;
}

void BandwidthSampler::OnPacketNeutered(PacketNumber packetNumber) {
    connectionStateMap_.Remove(packetNumber, [this](ConnectionStateOnSentPacket& sentPacket) {
        totalBytesNeutered_ += sentPacket.Size;
    });
}

void BandwidthSampler::OnAppLimited() {
    isAppLimited_ = true;
    endOfAppLimitedPhase_ = lastSentPacket_;
}

void BandwidthSampler::RemoveObsoletePackets(PacketNumber leastUnacked) {
    // A packet can become obsolete when it is removed from QuicUnackedPacketMap's
    // view of inflight before it is acked or marked as lost.
    connectionStateMap_.RemoveUpTo(leastUnacked);
}

ByteCount BandwidthSampler::TrackedPacketSize(PacketNumber packetNumber) const {
    const ConnectionStateOnSentPacket* sentPacketPointer = connectionStateMap_.GetEntry(packetNumber);
    if (sentPacketPointer == nullptr) {
        return 0;
    }
    return sentPacketPointer->Size;
}

bool BandwidthSampler::ChooseA0Point(ByteCount totalBytesAcked, AckPoint& a0) {
    if (a0Candidates_.Empty()) {
        return false;
    }

    if (a0Candidates_.Len() == 1) {
        a0 = *a0Candidates_.Front();
        return true;
    }

    for (std::size_t i = 1; i < a0Candidates_.Len(); i++) {
        if (a0Candidates_.Offset(i)->TotalBytesAcked > totalBytesAcked) {
            a0 = *a0Candidates_.Offset(i - 1);
            if (i > 1) {
                for (std::size_t j = 0; j < i - 1; j++) {
                    a0Candidates_.PopFront();
                }
            }
            return true;
        }
    }

    a0 = *a0Candidates_.Back();
    std::size_t popCount = a0Candidates_.Len() - 1;
    for (std::size_t k = 0; k < popCount; k++) {
        a0Candidates_.PopFront();
    }
    return true;
}

BandwidthSample BandwidthSampler::OnPacketAcknowledged(MonoTime ackTime,
                                                       PacketNumber packetNumber) {
    BandwidthSample sample;
    lastAckedPacket_ = packetNumber;
    const ConnectionStateOnSentPacket* sentPacketPointer = connectionStateMap_.GetEntry(packetNumber);
    if (sentPacketPointer == nullptr) {
        return sample;
    }

    // OnPacketAcknowledgedInner
    totalBytesAcked_ += sentPacketPointer->Size;
    totalBytesSentAtLastAckedPacket_ = sentPacketPointer->state.TotalBytesSent;
    lastAckedPacketSentTime_ = sentPacketPointer->SentTime;
    lastAckedPacketAckTime_ = ackTime;
    if (overestimateAvoidance_) {
        recentAckPoints_.Update(ackTime, totalBytesAcked_);
    }

    if (isAppLimited_) {
        // Exit app-limited phase in two cases:
        // (1) endOfAppLimitedPhase_ is not initialized, i.e., so far all
        //     packets are sent while there are buffered packets or pending data.
        // (2) The current acked packet is after the sent packet marked as the
        //     end of the app limit phase.
        if (endOfAppLimitedPhase_ == kInvalidPacketNumber ||
            packetNumber > endOfAppLimitedPhase_) {
            isAppLimited_ = false;
        }
    }

    // There might have been no packets acknowledged at the moment when the
    // current packet was sent. In that case, there is no bandwidth sample to
    // make.
    if (sentPacketPointer->LastAckedPacketSentTime.IsZero()) {
        return sample;
    }

    // Infinite rate indicates that the sampler is supposed to discard the
    // current send rate sample and use only the ack rate.
    Bandwidth sendRate = kInfBandwidth;
    if (sentPacketPointer->SentTime > sentPacketPointer->LastAckedPacketSentTime) {
        sendRate = BandwidthFromDelta(
            sentPacketPointer->state.TotalBytesSent -
                sentPacketPointer->TotalBytesSentAtLastAckedPacket,
            Duration(sentPacketPointer->SentTime.Sub(sentPacketPointer->LastAckedPacketSentTime)));
    }

    AckPoint a0;
    if (!(overestimateAvoidance_ &&
          ChooseA0Point(sentPacketPointer->state.TotalBytesAcked, a0))) {
        a0.AckTime = sentPacketPointer->LastAckedPacketAckTime;
        a0.TotalBytesAcked = sentPacketPointer->state.TotalBytesAcked;
    }

    // During the slope calculation, ensure that ack time of the current packet
    // is always larger than the time of the previous packet, otherwise division
    // by zero or integer underflow can occur.
    if (ackTime.Sub(a0.AckTime) <= 0) {
        return sample;
    }

    Bandwidth ackRate =
        BandwidthFromDelta(totalBytesAcked_ - a0.TotalBytesAcked, Duration(ackTime.Sub(a0.AckTime)));

    // Note: this sample does not account for delayed acknowledgement time.
    // This means that the RTT measurements here can be artificially high,
    // especially on low bandwidth connections.
    sample.BandwidthBps = std::min(sendRate, ackRate);
    sample.Rtt = Duration(ackTime.Sub(sentPacketPointer->SentTime));
    sample.SendRate = sendRate;
    SentPacketToSendTimeState(*sentPacketPointer, sample.StateAtSend);

    return sample;
}

ByteCount BandwidthSampler::OnAckEventEnd(Bandwidth bandwidthEstimate, bool isNewMaxBandwidth,
                                          RoundTripCount roundTripCount) {
    ByteCount newlyAckedBytes = totalBytesAcked_ - totalBytesAckedAfterLastAckEvent_;
    if (newlyAckedBytes == 0) {
        return 0;
    }
    totalBytesAckedAfterLastAckEvent_ = totalBytesAcked_;
    ByteCount extraAcked = maxAckHeightTracker_.Update(
        bandwidthEstimate, isNewMaxBandwidth, roundTripCount, lastSentPacket_, lastAckedPacket_,
        lastAckedPacketAckTime_, newlyAckedBytes);
    // If |extraAcked| is zero, i.e. this ack event marks the start of a new ack
    // aggregation epoch, save LessRecentPoint, which is the last ack point of
    // the previous epoch, as an A0 candidate.
    if (overestimateAvoidance_ && extraAcked == 0) {
        a0Candidates_.PushBack(recentAckPoints_.LessRecentPoint());
    }
    return extraAcked;
}

void SentPacketToSendTimeState(const ConnectionStateOnSentPacket& sentPacket,
                               SendTimeState& sendTimeState) {
    sendTimeState = sentPacket.state;
    sendTimeState.IsValid = true;
}

} // namespace hy2::bbr
