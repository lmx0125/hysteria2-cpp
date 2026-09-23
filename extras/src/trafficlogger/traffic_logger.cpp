// traffic_logger.cpp - Traffic stats HTTP API server.
// Rewrite of extras/trafficlogger/http.go.
#include "hy2/trafficlogger/traffic_logger.hpp"

#include <sstream>

namespace hy2::trafficlogger {

TrafficStatsServer::TrafficStatsServer(const std::string& secret)
    : secret_(secret) {}

bool TrafficStatsServer::LogTraffic(const std::string& id, uint64_t tx, uint64_t rx) {
    std::lock_guard<std::mutex> lk(mutex_);

    // One lookup instead of three. This runs once per relayed UDP datagram and
    // per 32KB of relayed TCP, so the string-keyed probes are the hot part.
    // (The old `kicked_.count(id) && kicked_[id]` also *inserted* a false entry
    // for every id it had never seen, growing the map without bound.)
    if (kicked_.find(id) != kicked_.end()) return false;

    auto it = stats_.try_emplace(id).first;
    it->second.tx += tx;
    it->second.rx += rx;
    return true;
}

void TrafficStatsServer::LogOnlineState(const std::string& id, bool online) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto& s = stats_[id];
    if (online) {
        s.connectionCount++;
        s.online = true;
    } else {
        s.connectionCount--;
        if (s.connectionCount <= 0) {
            s.connectionCount = 0;
            s.online = false;
        }
    }
}

std::string TrafficStatsServer::GetTrafficJSON(bool clearAfter) {
    std::lock_guard<std::mutex> lk(mutex_);
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (auto& [id, s] : stats_) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << id << "\":{\"tx\":" << s.tx << ",\"rx\":" << s.rx << "}";
    }
    oss << "}";
    if (clearAfter) {
        for (auto& [id, s] : stats_) {
            s.tx = 0;
            s.rx = 0;
        }
    }
    return oss.str();
}

std::string TrafficStatsServer::GetOnlineJSON() {
    std::lock_guard<std::mutex> lk(mutex_);
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (auto& [id, s] : stats_) {
        if (!s.online) continue;
        if (!first) oss << ",";
        first = false;
        oss << "\"" << id << "\":" << s.connectionCount;
    }
    oss << "}";
    return oss.str();
}

int TrafficStatsServer::KickUsers(const std::string& ids) {
    std::lock_guard<std::mutex> lk(mutex_);
    int count = 0;
    std::istringstream iss(ids);
    std::string id;
    while (std::getline(iss, id, ',')) {
        // Trim whitespace
        size_t start = id.find_first_not_of(" \t");
        size_t end = id.find_last_not_of(" \t");
        if (start != std::string::npos) {
            id = id.substr(start, end - start + 1);
        }
        if (!id.empty()) {
            kicked_.insert(id);
            count++;
        }
    }
    return count;
}

std::string TrafficStatsServer::GetStreamDump() {
    std::lock_guard<std::mutex> lk(mutex_);
    std::ostringstream oss;
    for (auto& [id, s] : stats_) {
        oss << id << "\t"
            << (s.online ? "online" : "offline") << "\t"
            << "tx=" << s.tx << "\t"
            << "rx=" << s.rx << "\n";
    }
    return oss.str();
}

bool TrafficStatsServer::Authorize(const std::string& authHeader) const {
    if (secret_.empty()) return true; // no auth required
    if (authHeader.empty()) return false;
    // Check "Authorization: <secret>" or just "<secret>"
    return authHeader == secret_;
}

} // namespace hy2::trafficlogger
