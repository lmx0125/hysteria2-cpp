// traffic_logger_test.cpp - Tests for traffic stats HTTP API.
#include "hytest.hpp"
#include "hy2/trafficlogger/traffic_logger.hpp"

using namespace hy2::trafficlogger;

HY_TEST(TrafficLogger_LogTraffic) {
    TrafficStatsServer tl;
    HY_CHECK(tl.LogTraffic("user1", 100, 200));
    HY_CHECK(tl.LogTraffic("user1", 50, 75));

    std::string json = tl.GetTrafficJSON();
    HY_CHECK(json.find("user1") != std::string::npos);
    HY_CHECK(json.find("\"tx\":150") != std::string::npos);
    HY_CHECK(json.find("\"rx\":275") != std::string::npos);
}

HY_TEST(TrafficLogger_OnlineState) {
    TrafficStatsServer tl;
    tl.LogOnlineState("user1", true);
    tl.LogOnlineState("user1", true); // second connection

    std::string online = tl.GetOnlineJSON();
    HY_CHECK(online.find("user1") != std::string::npos);
    HY_CHECK(online.find("2") != std::string::npos); // 2 connections

    tl.LogOnlineState("user1", false);
    online = tl.GetOnlineJSON();
    HY_CHECK(online.find("user1") != std::string::npos); // still 1 connection

    tl.LogOnlineState("user1", false);
    online = tl.GetOnlineJSON();
    HY_CHECK(online.find("user1") == std::string::npos); // offline
}

HY_TEST(TrafficLogger_KickUser) {
    TrafficStatsServer tl;
    HY_CHECK(tl.LogTraffic("user1", 100, 200));

    int kicked = tl.KickUsers("user1");
    HY_CHECK(kicked == 1);

    // Kicked user should not be able to log traffic
    HY_CHECK(tl.LogTraffic("user1", 50, 50) == false);
}

HY_TEST(TrafficLogger_ClearAfterRead) {
    TrafficStatsServer tl;
    tl.LogTraffic("user1", 100, 200);

    std::string json = tl.GetTrafficJSON(true); // clear after read
    HY_CHECK(json.find("100") != std::string::npos);

    // After clear, tx/rx should be 0
    json = tl.GetTrafficJSON();
    HY_CHECK(json.find("\"tx\":0") != std::string::npos);
}

HY_TEST(TrafficLogger_Authorize) {
    TrafficStatsServer tl("mysecret");
    HY_CHECK(tl.Authorize("mysecret"));
    HY_CHECK(!tl.Authorize("wrong"));
    HY_CHECK(!tl.Authorize(""));
}

HY_TEST(TrafficLogger_NoAuth) {
    TrafficStatsServer tl; // no secret
    HY_CHECK(tl.Authorize(""));
    HY_CHECK(tl.Authorize("anything"));
}

HY_TEST(TrafficLogger_StreamDump) {
    TrafficStatsServer tl;
    tl.LogOnlineState("user1", true);
    tl.LogTraffic("user1", 100, 200);

    std::string dump = tl.GetStreamDump();
    HY_CHECK(dump.find("user1") != std::string::npos);
    HY_CHECK(dump.find("online") != std::string::npos);
}
