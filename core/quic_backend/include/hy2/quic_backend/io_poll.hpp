#pragma once

// io_poll.hpp - single cross-platform blocking event wait for the QUIC
// backend. Replaces the polling loops (fixed sleep) and the dead EventLoop:
// both the client's InternalLoop and the server's RecvLoop block here until
// one of {socket data, wake signal, QUIC timer deadline} occurs.
//
//   Linux:   poll(2)
//   Windows: WSAPoll (same semantics; works on UDP sockets)
//
// Rationale (see ARCHITECTURE_REDESIGN.md):
//   A fixed-cadence sleep means packets leave LATER than the application
//   submitted them, inflating every RTT sample, which slows cwnd growth.
//   Blocking on the actual event sources makes the send time equal the
//   submit time, so RTT samples measure the network, not our scheduler.

#include <chrono>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
#else
  #include <poll.h>
#endif

namespace hy2::quic_backend {

enum class IoWaitResult {
    kEvent,   // readable on at least one of the fds (caller drains both)
    kTimeout, // deadline elapsed (QUIC timer due)
    kError,   // hard failure (e.g. no fds, invalid fd)
};

// Blocking wait until `fd` or `wakeFd` is readable, or until `deadline`.
// `deadline == time_point::max()` waits indefinitely.
// - fd < 0 and wakeFd < 0 => kError (nothing to wait on).
// - Spurious wakeups / EINTR are retried internally.
// - Error events on an fd (e.g. ICMP unreachable on a connected UDP socket)
//   are surfaced as kEvent; the caller's recv() consumes the error.
inline IoWaitResult IoWait(int fd, int wakeFd,
                           std::chrono::steady_clock::time_point deadline) {
    struct pollfd fds[2];
    int nfds = 0;
    if (fd >= 0) {
        fds[nfds].fd = fd;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        ++nfds;
    }
    if (wakeFd >= 0) {
        fds[nfds].fd = wakeFd;
        fds[nfds].events = POLLIN;
        fds[nfds].revents = 0;
        ++nfds;
    }
    if (nfds == 0) return IoWaitResult::kError;

    for (;;) {
        auto now = std::chrono::steady_clock::now();
        int64_t timeoutMs = -1; // infinite
        if (deadline != std::chrono::steady_clock::time_point::max()) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - now);
            if (remaining.count() < 0) {
                // Deadline already passed. Poll once with a small floor
                // instead of 0: a 0ms timeout would make the caller's
                // timer processing (e.g. ngtcp2's pacing expiry, which is
                // re-armed only by a packet send) busy-spin at 100% CPU.
                // Data/wake events still return immediately - the floor
                // only paces the pure-timer path.
                timeoutMs = 1;
            } else {
                timeoutMs = remaining.count();
            }
        }
        if (timeoutMs > 1000000) timeoutMs = 1000000; // poll() caps at ~int; keep sane

#ifdef _WIN32
        int rv = WSAPoll(fds, nfds, static_cast<int>(timeoutMs));
        int err = rv < 0 ? WSAGetLastError() : 0;
#else
        int rv = ::poll(fds, nfds, static_cast<int>(timeoutMs));
        int err = rv < 0 ? errno : 0;
#endif
        if (rv > 0) return IoWaitResult::kEvent;
        if (rv == 0) return IoWaitResult::kTimeout;
        // Interrupted: retry. Anything else is a hard failure.
#ifdef _WIN32
        if (err != WSAEINTR) return IoWaitResult::kError;
#else
        if (err != EINTR) return IoWaitResult::kError;
#endif
    }
}

} // namespace hy2::quic_backend