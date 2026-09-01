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

} // namespace hy2::server
