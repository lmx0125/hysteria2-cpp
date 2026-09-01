// frag.hpp - UDP message fragmentation. Rewrite of core/internal/frag.
#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "hy2/protocol.hpp"

namespace hy2::frag {

// FragUDPMessage fragments a UDP message so that each fragment is at most
// maxSize bytes on the wire. If the message fits, returns {m}. If the header
// alone exceeds maxSize, returns an empty vector (nil in Go).
std::vector<proto::UDPMessage> FragUDPMessage(const proto::UDPMessage& m, size_t maxSize);

// Defragger handles the defragmentation of UDP messages.
// The current implementation can only handle one packet ID at a time.
// If another packet arrives before a packet has received all fragments
// in their entirety, any previous state is discarded.
class Defragger {
public:
    // Feed feeds a fragment in. Returns a complete message when all fragments
    // of a packet have arrived (with Data reassembled and FragID=0/FragCount=1),
    // or nullptr if more fragments are needed / the input is bogus.
    std::shared_ptr<const proto::UDPMessage> Feed(const proto::UDPMessage& m);

private:
    uint16_t pktID_ = 0;
    std::vector<std::shared_ptr<const proto::UDPMessage>> frags_;
    uint8_t count_ = 0;
    size_t size_ = 0; // data size
};

} // namespace hy2::frag
