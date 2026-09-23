// traffic_logger.hpp - Traffic stats HTTP API server.
// Rewrite of extras/trafficlogger/http.go.
#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "hy2/server_iface.hpp"

namespace hy2::trafficlogger {

// TrafficStats tracks per-user traffic and online state.
struct TrafficStats {
    uint64_t tx = 0;
    uint64_t rx = 0;
    bool online = false;
    int connectionCount = 0;
};

// TrafficStatsServer implements ITrafficLogger and serves an HTTP API
// for querying traffic stats, kicking users, and viewing online state.
// Matches Go's extras/trafficlogger/http.go API endpoints.
class TrafficStatsServer : public server::ITrafficLogger {
public:
    explicit TrafficStatsServer(const std::string& secret = "");

    // ITrafficLogger interface
    bool LogTraffic(const std::string& id, uint64_t tx, uint64_t rx) override;
    void LogOnlineState(const std::string& id, bool online) override;

    // Get traffic stats for all users (JSON format)
    std::string GetTrafficJSON(bool clearAfter = false);

    // Get online users (JSON format)
    std::string GetOnlineJSON();

    // Kick users by ID list (comma-separated)
    // Returns the number of users kicked.
    int KickUsers(const std::string& ids);

    // Get stream dump (text format)
    std::string GetStreamDump();

    // Verify authorization header
    bool Authorize(const std::string& authHeader) const;

private:
    std::string secret_;
    std::mutex mutex_;
    std::unordered_map<std::string, TrafficStats> stats_;
    std::unordered_set<std::string> kicked_; // kicked user IDs
};

} // namespace hy2::trafficlogger
