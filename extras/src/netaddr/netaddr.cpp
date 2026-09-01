// netaddr.cpp - implementation of netaddr.hpp.
#include "hy2/netaddr.hpp"

#include <cstdint>
#include <vector>

namespace hy2 {

namespace {

std::string addrErrorText(const std::string& addr, const char* why) {
    // Go net.AddrError.Error(): "address <addr>: <err>", or just "<err>"
    // when the address is empty.
    if (addr.empty()) return why;
    return "address " + addr + ": " + why;
}

bool parseIPv4Strict(const std::string& s, uint8_t out[4]) {
    size_t pos = 0;
    for (int i = 0; i < 4; i++) {
        if (i > 0) {
            if (pos >= s.size() || s[pos] != '.') return false;
            pos++;
        }
        size_t start = pos;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') pos++;
        size_t nd = pos - start;
        if (nd < 1 || nd > 3) return false;
        if (nd > 1 && s[start] == '0') return false; // no leading zeros (Go netip)
        unsigned v = 0;
        for (size_t k = start; k < pos; k++) v = v * 10 + static_cast<unsigned>(s[k] - '0');
        if (v > 255) return false;
        out[i] = static_cast<uint8_t>(v);
    }
    return pos == s.size();
}

bool hexGroup(const std::string& g, uint16_t& out) {
    if (g.empty() || g.size() > 4) return false;
    unsigned v = 0;
    for (char c : g) {
        unsigned d;
        if (c >= '0' && c <= '9') d = static_cast<unsigned>(c - '0');
        else if (c >= 'a' && c <= 'f') d = static_cast<unsigned>(c - 'a') + 10;
        else if (c >= 'A' && c <= 'F') d = static_cast<unsigned>(c - 'A') + 10;
        else return false;
        v = (v << 4) | d;
    }
    out = static_cast<uint16_t>(v);
    return true;
}

std::vector<std::string> splitColon(const std::string& s) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); i++) {
        if (i == s.size() || s[i] == ':') {
            parts.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return parts;
}

// Parses the group list (no "::" inside); a trailing IPv4 dotted quad is
// expanded into two groups. Appends to groups.
bool parseGroups(const std::vector<std::string>& segs, std::vector<uint16_t>& groups) {
    for (size_t i = 0; i < segs.size(); i++) {
        const std::string& seg = segs[i];
        if (seg.empty()) return false;
        if (seg.find('.') != std::string::npos) {
            if (i + 1 != segs.size() || groups.size() + 2 > 8) return false;
            uint8_t v4[4];
            if (!parseIPv4Strict(seg, v4)) return false;
            groups.push_back(static_cast<uint16_t>((v4[0] << 8) | v4[1]));
            groups.push_back(static_cast<uint16_t>((v4[2] << 8) | v4[3]));
        } else {
            uint16_t g;
            if (!hexGroup(seg, g)) return false;
            groups.push_back(g);
        }
    }
    return true;
}

bool parseIPv6(const std::string& s, uint16_t groupsOut[8], bool& v4Tail) {
    if (s.empty() || s.find('%') != std::string::npos) return false;
    std::vector<uint16_t> groups;
    size_t dbl = s.find("::");
    if (dbl != std::string::npos) {
        if (s.find("::", dbl + 1) != std::string::npos) return false;
        std::string left = s.substr(0, dbl);
        std::string right = s.substr(dbl + 2);
        auto ls = left.empty() ? std::vector<std::string>{} : splitColon(left);
        auto rs = right.empty() ? std::vector<std::string>{} : splitColon(right);
        if (!parseGroups(ls, groups)) return false;
        size_t leftCount = groups.size();
        if (!parseGroups(rs, groups)) return false;
        size_t total = groups.size();
        // With an ellipsis at most 7 explicit groups (Go semantics).
        if (total >= 8) return false;
        size_t rc = total - leftCount;
        for (size_t i = 0; i < leftCount; i++) groupsOut[i] = groups[i];
        for (size_t i = 0; i < rc; i++) groupsOut[8 - rc + i] = groups[leftCount + i];
        for (size_t i = leftCount; i < 8 - rc; i++) groupsOut[i] = 0;
        v4Tail = rc > 0 && !rs.empty() && rs.back().find('.') != std::string::npos;
    } else {
        auto segs = splitColon(s);
        if (segs.size() != 8) return false;
        if (!parseGroups(segs, groups) || groups.size() != 8) return false;
        for (int i = 0; i < 8; i++) groupsOut[i] = groups[i];
        v4Tail = segs.back().find('.') != std::string::npos;
    }
    return true;
}

void appendHexGroup(std::string& r, uint16_t g) {
    static const char hex[] = "0123456789abcdef";
    if (g == 0) {
        r += "0";
        return;
    }
    bool started = false;
    for (int shift = 12; shift >= 0; shift -= 4) {
        unsigned d = (g >> shift) & 0xf;
        if (d != 0 || started) {
            r += hex[d];
            started = true;
        }
    }
}

std::string formatIPv6(const uint16_t g[8], bool v4Tail) {
    int n = v4Tail ? 6 : 8;
    int best = -1, bestLen = 0, cur = -1, curLen = 0;
    for (int i = 0; i < n; i++) {
        if (g[i] == 0) {
            if (cur < 0) {
                cur = i;
                curLen = 1;
            } else {
                curLen++;
            }
            if (curLen > bestLen) {
                best = cur;
                bestLen = curLen;
            }
        } else {
            cur = -1;
        }
    }
    std::string r;
    auto appendDottedTail = [&](int hiIdx) {
        // groups[hiIdx] = a<<8|b, groups[hiIdx+1] = c<<8|d
        uint32_t words[2] = {g[hiIdx], g[hiIdx + 1]};
        bool first = true;
        for (int w = 0; w < 2; w++) {
            for (int m : {12, 8, 4, 0}) {
                if (!first) r += '.';
                first = false;
                r += std::to_string((words[w] >> m) & 0xff);
            }
        }
    };
    auto joinRange = [&](int from, int to) {
        for (int i = from; i < to; i++) {
            if (i > from) r += ':';
            appendHexGroup(r, g[i]);
        }
    };
    if (best >= 0 && bestLen >= 2) {
        joinRange(0, best);
        r += "::";
        if (best + bestLen < n) {
            if (v4Tail) {
                appendDottedTail(best + bestLen);
            } else {
                joinRange(best + bestLen, n);
            }
        }
    } else {
        joinRange(0, n - 2);
        if (v4Tail) {
            r += ':';
            appendDottedTail(n - 2);
        }
    }
    return r;
}

} // namespace

std::optional<std::pair<std::string, std::string>> SplitHostPort(
    const std::string& hostPort, std::string& errOut) {
    // Faithful port of Go net.SplitHostPort.
    errOut.clear();
    size_t i = hostPort.rfind(':');
    if (i == std::string::npos) {
        errOut = addrErrorText(hostPort, "missing port in address");
        return std::nullopt;
    }

    std::string host;
    size_t j = 0, k = 0;
    if (hostPort[0] == '[') {
        size_t end = hostPort.find(']');
        if (end == std::string::npos) {
            errOut = addrErrorText(hostPort, "missing ']' in address");
            return std::nullopt;
        }
        if (end + 1 == hostPort.size()) {
            errOut = addrErrorText(hostPort, "missing port in address");
            return std::nullopt;
        } else if (end + 1 != i) {
            if (hostPort[end + 1] == ':') {
                errOut = addrErrorText(hostPort, "too many colons in address");
            } else {
                errOut = addrErrorText(hostPort, "missing port in address");
            }
            return std::nullopt;
        }
        host = hostPort.substr(1, end - 1);
        j = 1;
        k = end + 1; // there can't be a '[' resp. ']' before these positions
    } else {
        host = hostPort.substr(0, i);
        if (host.find(':') != std::string::npos) {
            errOut = addrErrorText(hostPort, "too many colons in address");
            return std::nullopt;
        }
    }
    if (hostPort.find('[', j) != std::string::npos) {
        errOut = addrErrorText(hostPort, "unexpected '[' in address");
        return std::nullopt;
    }
    if (hostPort.find(']', k) != std::string::npos) {
        errOut = addrErrorText(hostPort, "unexpected ']' in address");
        return std::nullopt;
    }
    return std::make_pair(host, hostPort.substr(i + 1));
}

std::string JoinHostPort(const std::string& host, const std::string& port) {
    // We assume that host is a literal IPv6 address if host has colons.
    if (host.find(':') != std::string::npos) {
        return "[" + host + "]:" + port;
    }
    return host + ":" + port;
}

bool IsIP(const std::string& s) {
    if (s.empty()) return false;
    uint8_t v4[4];
    if (parseIPv4Strict(s, v4)) return true;
    uint16_t g[8];
    bool v4Tail = false;
    return parseIPv6(s, g, v4Tail);
}

std::string CanonicalizeIP(const std::string& s) {
    if (s.empty()) return "";
    uint8_t v4[4];
    if (parseIPv4Strict(s, v4)) return s;
    uint16_t g[8];
    bool v4Tail = false;
    if (parseIPv6(s, g, v4Tail)) return formatIPv6(g, v4Tail);
    return "";
}

} // namespace hy2
