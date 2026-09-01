// portunion.cpp - rewrite of extras/utils/portunion.go
#include "hy2/portunion.hpp"

#include <algorithm>
#include <cstdlib>
#include <optional>

#include "hy2/error.hpp"

namespace hy2 {

namespace {
std::optional<uint32_t> parseUint16(const std::string& s) {
    if (s.empty()) return std::nullopt;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
    }
    unsigned long v = 0;
    try {
        v = std::stoul(s);
    } catch (...) {
        return std::nullopt;
    }
    if (v > 65535) return std::nullopt;
    return static_cast<uint32_t>(v);
}

std::vector<std::string> splitString(const std::string& s, char sep) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); i++) {
        if (i == s.size() || s[i] == sep) {
            parts.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}
} // namespace

PortUnion NormalizePortUnion(PortUnion u) {
    if (u.empty()) {
        return u;
    }
    std::sort(u.begin(), u.end(), [](const PortRange& a, const PortRange& b) {
        if (a.Start == b.Start) {
            return a.End < b.End;
        }
        return a.Start < b.Start;
    });
    PortUnion normalized;
    normalized.push_back(u[0]);
    for (size_t i = 1; i < u.size(); i++) {
        const auto& current = u[i];
        auto& last = normalized.back();
        if (static_cast<uint32_t>(current.Start) <= static_cast<uint32_t>(last.End) + 1) {
            if (current.End > last.End) {
                last.End = current.End;
            }
        } else {
            normalized.push_back(current);
        }
    }
    return normalized;
}

std::vector<PortRange> ParsePortUnion(const std::string& s, bool& ok) {
    ok = false;
    if (s == "all" || s == "*") {
        // Wildcard special case
        ok = true;
        return PortUnion{PortRange{0, 65535}};
    }
    PortUnion result;
    auto portStrs = splitString(s, ',');
    for (const auto& portStr : portStrs) {
        if (portStr.find('-') != std::string::npos) {
            // Port range
            auto parts = splitString(portStr, '-');
            if (parts.size() != 2) {
                return {};
            }
            auto start = parseUint16(parts[0]);
            if (!start) return {};
            auto end = parseUint16(parts[1]);
            if (!end) return {};
            uint32_t st = *start, en = *end;
            if (st > en) std::swap(st, en);
            result.push_back(PortRange{static_cast<uint16_t>(st), static_cast<uint16_t>(en)});
        } else {
            // Single port
            auto port = parseUint16(portStr);
            if (!port) return {};
            result.push_back(
                PortRange{static_cast<uint16_t>(*port), static_cast<uint16_t>(*port)});
        }
    }
    if (result.empty()) {
        return {};
    }
    ok = true;
    return NormalizePortUnion(std::move(result));
}

PortUnion ParsePortUnionOrThrow(const std::string& s) {
    bool ok = false;
    auto u = ParsePortUnion(s, ok);
    if (!ok) {
        throw Error("invalid port union: " + s);
    }
    return u;
}

std::vector<uint16_t> PortUnionPorts(const PortUnion& u) {
    std::vector<uint16_t> ports;
    for (const auto& r : u) {
        for (uint32_t i = r.Start; i <= r.End; i++) {
            ports.push_back(static_cast<uint16_t>(i));
        }
    }
    return ports;
}

bool PortUnionContains(const PortUnion& u, uint16_t port) {
    for (const auto& r : u) {
        if (port >= r.Start && port <= r.End) {
            return true;
        }
    }
    return false;
}

} // namespace hy2
