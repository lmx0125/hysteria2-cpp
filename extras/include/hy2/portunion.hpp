// portunion.hpp - PortUnion parsing. Rewrite of extras/utils/portunion.go.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hy2 {

// PortRange represents a range of ports. Start and End are inclusive.
struct PortRange {
    uint16_t Start = 0;
    uint16_t End = 0;
};

// PortUnion is a collection of multiple port ranges.
using PortUnion = std::vector<PortRange>;

// ParsePortUnion parses a string of comma-separated port ranges (or single
// ports) into a PortUnion. Returns an empty optional-ish (nullopt) if the
// input is invalid. The returned PortUnion is guaranteed to be normalized.
// "all" / "*" => [0, 65535].
std::vector<PortRange> ParsePortUnion(const std::string& s, bool& ok);

// Convenience wrapper throwing on invalid input.
PortUnion ParsePortUnionOrThrow(const std::string& s);

// Normalize normalizes a PortUnion: no overlapping ranges, sorted low->high.
PortUnion NormalizePortUnion(PortUnion u);

// Ports returns all ports in the PortUnion.
std::vector<uint16_t> PortUnionPorts(const PortUnion& u);

// Contains returns true if the PortUnion contains the given port.
bool PortUnionContains(const PortUnion& u, uint16_t port);

} // namespace hy2
