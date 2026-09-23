// copy.hpp - Bidirectional copying with traffic logging.
// Rewrite of core/server/copy.go.
#pragma once

#include <functional>
#include <memory>
#include <string>

#include "hy2/io.hpp"
#include "hy2/server_iface.hpp"

namespace hy2::server {

// CopyBufferLog copies src to dst, calling log(bytesRead) before each write.
// If log returns false, throws ErrDisconnect (traffic logger requested disconnect).
void CopyBufferLog(IByteWriter& dst, IByteReader& src,
                   const std::function<bool(uint64_t)>& log);

// CopyTwoWayEx copies both ways between the client stream and the remote,
// updating stats and consulting the traffic logger. Blocks until one direction
// finishes or errors; returns the first error message (empty == clean EOF).
// When the first direction finishes, both sides are Close()d so the other
// direction terminates; ownership is shared, making this safe.
std::string CopyTwoWayEx(const std::string& id,
                         std::shared_ptr<IByteReaderWriter> serverRw,
                         std::shared_ptr<IByteReaderWriter> remoteRw,
                         ITrafficLogger* l, StreamStats& stats);

// CopyTwoWay is the "fast-path" version without logging/stats.
std::string CopyTwoWay(std::shared_ptr<IByteReaderWriter> serverRw,
                       std::shared_ptr<IByteReaderWriter> remoteRw);

// Copy-buffer pool counters, exposed for regression tests.
//   blocksFreshAllocs:        32KB blocks taken from the heap because the pool
//                             was empty (each one is a fresh allocation).
//   blocksReturnedToCentral:  blocks handed back to the shared central pool.
// A relay thread holds one block for its lifetime, so a healthy pool keeps
// blocksFreshAllocs near constant while blocksReturnedToCentral grows with the
// number of finished relays. If blocksFreshAllocs grows with the connection
// count, blocks are being leaked on thread exit (see TLSData's destructor).
struct CopyPoolStats {
    uint64_t blocksFreshAllocs = 0;
    uint64_t blocksReturnedToCentral = 0;
};
CopyPoolStats CopyPoolStatsSnapshot();

} // namespace hy2::server
