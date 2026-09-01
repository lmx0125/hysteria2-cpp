// quic_stats_test.cpp - Tests for QUIC stats analysis and reporting.
// Self-contained: no QUIC backend dependency.

#include "hytest.hpp"

#include <cmath>
#include <cstdint>
#include <sstream>
#include <string>

// ===========================================================================
// Analysis logic (extracted from benchmark infrastructure)
// ===========================================================================

struct MockQuicStats {
    uint64_t bytesSent = 0;
    uint64_t bytesReceived = 0;
    uint64_t packetsSent = 0;
    uint64_t packetsReceived = 0;
    uint64_t packetsLost = 0;
    uint64_t packetsRetransmitted = 0;
    double smoothedRttUs = 0;
    uint64_t cwnd = 0;
    uint64_t bytesInFlight = 0;
    uint64_t streamsOpen = 0;
    uint64_t streamsActive = 0;
};

struct MockSocketStats {
    uint64_t txSendSuccess = 0;
    uint64_t txQueueCount = 0;
    uint64_t txQueueDrop = 0;
    uint64_t txDrainSuccess = 0;
    uint64_t txDrainWouldBlock = 0;
    uint64_t txDrainError = 0;
    uint64_t rxPackets = 0;
    size_t txQueuePeak = 0;
};

struct AnalysisResult {
    std::string conclusion;
    bool isCwndLimited = false;
    bool isAppNotFillingCwnd = false;
    bool hasPacketLoss = false;
    bool hasRetransmissions = false;
    bool isTxQueueSaturated = false;
    bool isTxQueueNotBottleneck = false;
    double theoreticalThroughputMBs = 0;
};

AnalysisResult analyzeQuicStats(
    double rttMs,
    uint64_t cwndBytes,
    uint64_t inflightBytes,
    uint64_t packetsLost,
    uint64_t packetsRetransmitted,
    uint64_t txQueuePeak,
    uint64_t txDrainWouldBlock,
    uint64_t packetsSent)
{
    AnalysisResult r;

    if (rttMs > 0) {
        double rttSec = rttMs / 1000.0;
        r.theoreticalThroughputMBs = static_cast<double>(cwndBytes) / rttSec / (1024.0 * 1024.0);
    }

    if (cwndBytes > 0) {
        double ratio = static_cast<double>(inflightBytes) / static_cast<double>(cwndBytes);
        r.isCwndLimited = (ratio >= 0.8);
        r.isAppNotFillingCwnd = (ratio < 0.5);
    }

    r.hasPacketLoss = (packetsLost > 0);
    r.hasRetransmissions = (packetsRetransmitted > 0);
    r.isTxQueueSaturated = (txQueuePeak >= 200);
    r.isTxQueueNotBottleneck = (txQueuePeak < 10 && txDrainWouldBlock < 5);

    return r;
}

std::string formatAnalysis(
    double rttMs,
    uint64_t cwndBytes,
    uint64_t inflightBytes,
    uint64_t packetsLost,
    uint64_t packetsRetransmitted,
    uint64_t txQueuePeak,
    uint64_t txDrainWouldBlock,
    uint64_t packetsSent,
    double actualThroughputMBs)
{
    auto r = analyzeQuicStats(rttMs, cwndBytes, inflightBytes,
                              packetsLost, packetsRetransmitted,
                              txQueuePeak, txDrainWouldBlock, packetsSent);

    std::ostringstream oss;
    oss << "=================================\n";
    oss << "HY2-C++ QUIC ANALYSIS REPORT\n";
    oss << "=================================\n\n";
    oss << "RTT:                " << rttMs << " ms\n";
    oss << "CWND:               " << (cwndBytes / (1024.0 * 1024.0)) << " MB\n";
    oss << "Inflight:           " << (inflightBytes / (1024.0 * 1024.0)) << " MB\n";
    oss << "Theoretical Max:    " << r.theoreticalThroughputMBs << " MB/s\n";
    oss << "Actual Throughput:  " << actualThroughputMBs << " MB/s\n\n";

    if (r.isCwndLimited) oss << "[!] Connection is CWND-limited.\n";
    else if (r.isAppNotFillingCwnd) oss << "[!] Application is not filling the congestion window.\n";
    else oss << "[OK] CWND utilization is healthy.\n";

    if (r.hasPacketLoss) {
        double lossRate = (packetsSent > 0) ?
            (static_cast<double>(packetsLost) / packetsSent * 100.0) : 0;
        oss << "[!] Packet loss detected. Loss rate: " << lossRate << "%\n";
    }
    if (r.hasRetransmissions) {
        oss << "[!] Retransmissions detected: " << packetsRetransmitted << "\n";
    }
    if (r.isTxQueueSaturated) {
        oss << "[!] TX queue saturation detected (peak=" << txQueuePeak << ").\n";
    } else if (r.isTxQueueNotBottleneck) {
        oss << "[OK] TX queue is not the bottleneck.\n";
    }

    return oss.str();
}

// ===========================================================================
// Tests
// ===========================================================================

HY_TEST(StatsStruct_Defaults) {
    MockQuicStats qs;
    HY_CHECK_EQ(qs.bytesSent, 0u);
    HY_CHECK_EQ(qs.packetsSent, 0u);
    HY_CHECK_EQ(qs.packetsLost, 0u);
    HY_CHECK_EQ(qs.cwnd, 0u);
    HY_CHECK_EQ(qs.bytesInFlight, 0u);

    MockSocketStats ss;
    HY_CHECK_EQ(ss.txSendSuccess, 0u);
    HY_CHECK_EQ(ss.txQueuePeak, 0u);
    HY_CHECK_EQ(ss.txDrainWouldBlock, 0u);
}

HY_TEST(Analysis_CwndLimited) {
    auto r = analyzeQuicStats(165.0, 8*1024*1024, 7*1024*1024, 0, 0, 5, 0, 1000);
    HY_CHECK(r.isCwndLimited);
    HY_CHECK(!r.isAppNotFillingCwnd);
    HY_CHECK(!r.hasPacketLoss);
    HY_CHECK(!r.isTxQueueSaturated);
    HY_CHECK(r.isTxQueueNotBottleneck);
}

HY_TEST(Analysis_AppNotFillingCwnd) {
    auto r = analyzeQuicStats(165.0, 8*1024*1024, 3*1024*1024, 0, 0, 5, 0, 1000);
    HY_CHECK(!r.isCwndLimited);
    HY_CHECK(r.isAppNotFillingCwnd);
}

HY_TEST(Analysis_PacketLoss) {
    auto r = analyzeQuicStats(165.0, 8*1024*1024, 7*1024*1024, 10, 5, 5, 0, 1000);
    HY_CHECK(r.hasPacketLoss);
    HY_CHECK(r.hasRetransmissions);
}

HY_TEST(Analysis_TxQueueSaturated) {
    auto r = analyzeQuicStats(165.0, 8*1024*1024, 7*1024*1024, 0, 0, 240, 50, 1000);
    HY_CHECK(r.isTxQueueSaturated);
    HY_CHECK(!r.isTxQueueNotBottleneck);
}

HY_TEST(Analysis_TxQueueNotBottleneck) {
    auto r = analyzeQuicStats(165.0, 8*1024*1024, 7*1024*1024, 0, 0, 3, 0, 1000);
    HY_CHECK(!r.isTxQueueSaturated);
    HY_CHECK(r.isTxQueueNotBottleneck);
}

HY_TEST(Analysis_TheoreticalThroughput) {
    auto r = analyzeQuicStats(165.0, 8*1024*1024, 7*1024*1024, 0, 0, 5, 0, 1000);
    double expected = 8.0 * 1024.0 * 1024.0 / 0.165 / (1024.0 * 1024.0);
    HY_CHECK(std::abs(r.theoreticalThroughputMBs - expected) < 1.0);
}

HY_TEST(FormatAnalysis_Output) {
    std::string output = formatAnalysis(165.0, 8*1024*1024, 7*1024*1024, 0, 0, 5, 0, 1000, 13.94);
    HY_CHECK(output.find("RTT:") != std::string::npos);
    HY_CHECK(output.find("165") != std::string::npos);
    HY_CHECK(output.find("CWND:") != std::string::npos);
    HY_CHECK(output.find("Inflight:") != std::string::npos);
    HY_CHECK(output.find("Theoretical Max:") != std::string::npos);
    HY_CHECK(output.find("Actual Throughput:") != std::string::npos);
    HY_CHECK(output.find("13.94") != std::string::npos);
    HY_CHECK(output.find("CWND-limited") != std::string::npos);
}

HY_TEST(FormatAnalysis_LossDetected) {
    std::string output = formatAnalysis(165.0, 8*1024*1024, 7*1024*1024, 10, 5, 5, 0, 1000, 10.0);
    HY_CHECK(output.find("Packet loss detected") != std::string::npos);
    HY_CHECK(output.find("Retransmissions detected") != std::string::npos);
}

HY_TEST(FormatAnalysis_TxQueueSaturated) {
    std::string output = formatAnalysis(165.0, 8*1024*1024, 7*1024*1024, 0, 0, 240, 50, 1000, 5.0);
    HY_CHECK(output.find("TX queue saturation") != std::string::npos);
}

HY_TEST(FormatAnalysis_TxQueueHealthy) {
    std::string output = formatAnalysis(165.0, 8*1024*1024, 7*1024*1024, 0, 0, 3, 0, 1000, 13.94);
    HY_CHECK(output.find("TX queue is not the bottleneck") != std::string::npos);
}

HY_TEST(Analysis_HighCwndLowInflight) {
    auto r = analyzeQuicStats(165.0, 64*1024*1024, 10*1024*1024, 0, 0, 5, 0, 1000);
    HY_CHECK(!r.isCwndLimited);
    HY_CHECK(r.isAppNotFillingCwnd);
    HY_CHECK(r.theoreticalThroughputMBs > 300.0);
}

HY_TEST(Analysis_ZeroRtt) {
    auto r = analyzeQuicStats(0.0, 8*1024*1024, 7*1024*1024, 0, 0, 5, 0, 1000);
    HY_CHECK_EQ(r.theoreticalThroughputMBs, 0.0);
}

HY_TEST(Analysis_ZeroCwnd) {
    auto r = analyzeQuicStats(165.0, 0, 0, 0, 0, 5, 0, 1000);
    HY_CHECK_EQ(r.theoreticalThroughputMBs, 0.0);
    HY_CHECK(!r.isCwndLimited);
    HY_CHECK(!r.isAppNotFillingCwnd);
}

HY_TEST(Analysis_HeavyLoss) {
    auto r = analyzeQuicStats(165.0, 8*1024*1024, 7*1024*1024, 500, 200, 5, 0, 1000);
    HY_CHECK(r.hasPacketLoss);
    HY_CHECK(r.hasRetransmissions);
    std::string output = formatAnalysis(165.0, 8*1024*1024, 7*1024*1024, 500, 200, 5, 0, 1000, 2.0);
    HY_CHECK(output.find("50") != std::string::npos);
}
