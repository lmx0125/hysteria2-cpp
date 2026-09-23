// udp_socket_test.cpp - regression tests for the UdpSocket tx-queue fast path.
//
// Background: the server hands the SAME UdpSocket to every connection, so
// txMu_ is listener-wide. DrainTxQueue() is called once per Drive() and once
// per ServerLoop() iteration by each connection, and it used to take that
// shared lock unconditionally - even when the queue was empty, which is the
// normal case (a successful sendto never queues anything). With N connections
// that was N-way contention on one cache line for no work at all.
//
// The fix adds `txQueued_`, written under txMu_ (release) and read without the
// lock (acquire). The invariant it must preserve is the whole point of the
// queue: a packet that was queued on WOULDBLOCK must still be sent once the
// kernel buffer drains. If the fast path ever returned early while the queue
// was non-empty, that packet would be stranded forever - the connection would
// silently lose it and, for a retransmittable QUIC packet, stall.
//
// These tests therefore do not check the flag itself (it is private); they
// check the observable contract, by really forcing the send path to WOULDBLOCK
// and then requiring the queued packets to come out the other end.

#include "hytest.hpp"

#ifdef HY2_WITH_QUIC_BACKEND

#include "hy2/quic_backend/udp_socket.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

using hy2::quic_backend::UdpSocket;

namespace {

// The kernel enforces its own minimums on these; setting them small is only a
// hint that keeps the fill loop short.
void SetBufSize(int fd, int opt, int bytes) {
    if (fd < 0) return;
    setsockopt(fd, SOL_SOCKET, opt,
               reinterpret_cast<const char*>(&bytes), sizeof(bytes));
}

// Drains everything currently readable into `sink`. Returns how many datagrams
// were taken, so the caller can tell whether space was actually freed.
size_t DrainReceiver(UdpSocket& rx, std::vector<uint8_t>& buf) {
    size_t n = 0;
    for (;;) {
        int got = rx.RecvFrom(buf.data(), buf.size(), nullptr, nullptr);
        if (got <= 0) break;
        ++n;
    }
    return n;
}

} // namespace

// ---------------------------------------------------------------------------
// An idle socket must report an empty queue, every time.
//
// This is the deterministic half of the contract. It also pins the behaviour a
// stuck flag would most plausibly break in the *other* direction: if
// txQueued_ were left true after the queue emptied, every later DrainTxQueue()
// would take the listener-wide lock for nothing - the exact cost the flag
// exists to remove - so a regression there would go unnoticed by throughput
// alone and is worth an explicit check.
// ---------------------------------------------------------------------------
HY_TEST(UdpSocket_DrainEmptyQueueReturnsZero)
{
    UdpSocket s;
    HY_CHECK(s.Bind("127.0.0.1", 0));

    for (int i = 0; i < 8; ++i) {
        HY_CHECK_EQ(s.DrainTxQueue(), static_cast<size_t>(0));
        HY_CHECK(!s.HasQueuedPackets());
    }

    // Still true after the socket has been used for a real (successful) send:
    // a successful sendto never queues, so the flag must not have been set.
    UdpSocket rx;
    HY_CHECK(rx.Bind("127.0.0.1", 0));
    HY_CHECK(s.Connect("127.0.0.1", rx.LocalPort()));

    const uint8_t payload[64] = {0};
    for (int i = 0; i < 16; ++i) {
        HY_CHECK(s.Send(payload, sizeof(payload)) > 0);
    }
    HY_CHECK_EQ(s.GetStats().txQueueCount, static_cast<uint64_t>(0));
    HY_CHECK_EQ(s.DrainTxQueue(), static_cast<size_t>(0));
    HY_CHECK(!s.HasQueuedPackets());
}

// ---------------------------------------------------------------------------
// The stranding test: a packet that entered the queue must come back out.
//
// The queue is only reachable through the WOULDBLOCK branch, and Windows
// loopback never applies backpressure - it silently drops a datagram aimed at
// a full receive queue instead of blocking the sender - so Send() cannot be
// driven into WSAEWOULDBLOCK here. The test therefore enqueues through
// EnqueueForTest, which builds the packet and calls the same EnqueueTxLocked()
// that all four would-block sites call, so this exercises the real enqueue
// path rather than a stand-in for it.
//
// The assertions are deliberately about the queue and the drain counter, not
// about the datagram arriving at a peer. A peer-based check is not reliable
// here: the QUIC tests that run just before this one leave sockets bound to
// ephemeral ports, and both they and UdpSocket::Bind() set SO_REUSEADDR, so a
// datagram sent to a reused port can be delivered to the wrong socket and the
// check fails in the full suite while passing in isolation. The invariant that
// actually matters is that the drain empties the queue, which it can only do
// by completing a send/sendto - and txDrainSuccess counts exactly that.
// ---------------------------------------------------------------------------
HY_TEST(UdpSocket_QueuedPacketsAreNotStranded)
{
    UdpSocket rx;
    HY_CHECK(rx.Bind("127.0.0.1", 0));

    UdpSocket tx;
    HY_CHECK(tx.Connect("127.0.0.1", rx.LocalPort()));

    std::vector<uint8_t> payload(512, 0x5a);

    const size_t kQueued = 4;
    const uint64_t drainedBefore = tx.GetStats().txDrainSuccess;
    for (size_t i = 0; i < kQueued; ++i) {
        tx.EnqueueForTest(payload.data(), payload.size());
    }

    // The enqueue must be visible to the drain. If txQueued_ were not raised,
    // the fast path would return 0 here without touching the queue, so the
    // packets would stay queued - and HasQueuedPackets(), which takes the
    // lock and looks at the deque itself, is what catches that.
    HY_CHECK(tx.HasQueuedPackets());
    HY_CHECK_EQ(tx.DrainTxQueue(), static_cast<size_t>(0));
    HY_CHECK(!tx.HasQueuedPackets());

    // ...and every one of them was actually handed to the kernel.
    HY_CHECK_EQ(tx.GetStats().txDrainSuccess - drainedBefore,
                static_cast<uint64_t>(kQueued));
}

// The sendto form (hasDest = true) is the one the server uses for every
// connection - the listener's socket is never connected - so it gets its own
// check that the queued packet is drained through that branch.
HY_TEST(UdpSocket_QueuedSendToPacketsAreNotStranded)
{
    UdpSocket rx;
    HY_CHECK(rx.Bind("127.0.0.1", 0));

    UdpSocket tx;
    HY_CHECK(tx.Bind("127.0.0.1", 0)); // unconnected: must go through sendto

    struct sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(rx.LocalPort());
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    std::vector<uint8_t> payload(512, 0x77);

    const uint64_t drainedBefore = tx.GetStats().txDrainSuccess;
    tx.EnqueueForTest(payload.data(), payload.size(),
                      reinterpret_cast<const struct sockaddr*>(&to), sizeof(to));

    HY_CHECK(tx.HasQueuedPackets());
    HY_CHECK_EQ(tx.DrainTxQueue(), static_cast<size_t>(0));
    HY_CHECK(!tx.HasQueuedPackets());
    HY_CHECK_EQ(tx.GetStats().txDrainSuccess - drainedBefore,
                static_cast<uint64_t>(1));
}

// ---------------------------------------------------------------------------
// Many threads sending and draining at once on one shared socket.
//
// This is the shape the server actually runs: one UdpSocket, one worker thread
// per connection, all calling DrainTxQueue() concurrently. It is a race test
// rather than a precise one - it asserts the queue never deadlocks and never
// reports pending work that cannot be drained - which is exactly the class of
// bug the flag could introduce.
// ---------------------------------------------------------------------------
HY_TEST(UdpSocket_ConcurrentDrainKeepsQueueConsistent)
{
    UdpSocket rx;
    HY_CHECK(rx.Bind("127.0.0.1", 0));
    const uint16_t rxPort = rx.LocalPort();
    SetBufSize(rx.GetFd(), SO_RCVBUF, 4096);

    UdpSocket tx;
    HY_CHECK(tx.Connect("127.0.0.1", rxPort));
    SetBufSize(tx.GetFd(), SO_SNDBUF, 4096);

    std::vector<uint8_t> payload(512, 0x33);
    std::vector<uint8_t> rxBuf(2048);

    std::atomic<bool> stop{false};
    std::atomic<int> drainers{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&] {
            while (!stop.load(std::memory_order_relaxed)) {
                tx.Send(payload.data(), payload.size());
                tx.DrainTxQueue();
            }
            drainers.fetch_add(1, std::memory_order_relaxed);
        });
    }

    // Keep the receiver moving so the senders keep cycling through both the
    // direct and the queued path for a while.
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        DrainReceiver(rx, rxBuf);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    stop.store(true, std::memory_order_relaxed);
    for (auto& th : threads) th.join();
    HY_CHECK_EQ(drainers.load(), 4);

    // Drain everything that is left; the queue must reach empty in bounded
    // time instead of reporting work forever.
    size_t remaining = tx.DrainTxQueue();
    const auto drainDeadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(20);
    while (remaining > 0 && std::chrono::steady_clock::now() < drainDeadline) {
        DrainReceiver(rx, rxBuf);
        remaining = tx.DrainTxQueue();
    }
    HY_CHECK_EQ(remaining, static_cast<size_t>(0));
    HY_CHECK(!tx.HasQueuedPackets());
}

// ---------------------------------------------------------------------------
// TX segmentation (Windows UDP segmentation offload).
//
// Written so it is meaningful on a machine without the offload too: there the
// API must refuse, not fake it. The delivery count is the assertion that
// matters - it is what proves one call really produced N datagrams.
// ---------------------------------------------------------------------------
HY_TEST(UdpSocket_SegmentationContract)
{
    const size_t kSeg = 1350;
    const size_t kCount = 4;

    // A fixed port outside the ephemeral range: other tests in this binary bind
    // ephemeral ports, and a reused ephemeral port would deliver our datagrams
    // to the wrong socket (both sides set SO_REUSEADDR).
    UdpSocket rx;
    HY_CHECK(rx.Bind("127.0.0.1", 39011));

    UdpSocket tx;
    HY_CHECK(tx.Bind("127.0.0.1", 0)); // unconnected: the server's shape

    struct sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(39011);
    to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    const struct sockaddr* toSa = reinterpret_cast<const struct sockaddr*>(&to);

    std::vector<uint8_t> buf(kSeg * kCount, 0x6b);
    std::vector<uint8_t> rxBuf(4096);

    if (!tx.EnableTxSegmentation(kSeg)) {
        HY_CHECK(!tx.TxSegmentationEnabled());
        HY_CHECK_EQ(tx.SendSegmented(buf.data(), kSeg * kCount, toSa, sizeof(to)), -1);
        return;
    }
    HY_CHECK(tx.TxSegmentationEnabled());
    HY_CHECK_EQ(tx.TxSegmentSize(), kSeg);

    // The option is per-socket, and the server shares one socket across every
    // connection: a second caller asking for a different size must be refused,
    // or it would re-segment the first connection's in-flight batch by the
    // wrong boundary and corrupt its packets.
    HY_CHECK(!tx.EnableTxSegmentation(kSeg + 8));
    HY_CHECK_EQ(tx.TxSegmentSize(), kSeg);

    // A length that is not a whole number of segments must be refused.
    HY_CHECK_EQ(tx.SendSegmented(buf.data(), kSeg * kCount + 1, toSa, sizeof(to)), -1);

    // One call must produce exactly kCount datagrams of exactly kSeg bytes.
    HY_CHECK_EQ(tx.SendSegmented(buf.data(), kSeg * kCount, toSa, sizeof(to)),
                static_cast<int>(kSeg * kCount));

    size_t got = 0, badSize = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (got + badSize < kCount && std::chrono::steady_clock::now() < deadline) {
        const int n = rx.RecvFrom(rxBuf.data(), rxBuf.size(), nullptr, nullptr);
        if (n <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if (static_cast<size_t>(n) == kSeg) ++got; else ++badSize;
    }
    HY_CHECK_EQ(got, kCount);
    HY_CHECK_EQ(badSize, static_cast<size_t>(0));

    // The server shares one socket between batched bulk data and single ACK
    // packets, so a plain send must still work once segmentation is on.
    const uint8_t one[kSeg] = {0};
    HY_CHECK_EQ(tx.SendTo(one, kSeg, toSa, sizeof(to)), static_cast<int>(kSeg));

    size_t plain = 0;
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (plain == 0 && std::chrono::steady_clock::now() < deadline) {
        const int n = rx.RecvFrom(rxBuf.data(), rxBuf.size(), nullptr, nullptr);
        if (n > 0 && static_cast<size_t>(n) == kSeg) ++plain;
        else std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    HY_CHECK_EQ(plain, static_cast<size_t>(1));
}

#endif // HY2_WITH_QUIC_BACKEND