// obfs_test.cpp - Port of extras/obfs tests (salamander_test.go,
// gecko_frame_test.go, gecko_test.go) plus BLAKE2b known-answer vectors.
#include "hytest.hpp"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "hy2/error.hpp"
#include "hy2/obfs/blake2b.hpp"
#include "hy2/obfs/gecko.hpp"
#include "hy2/obfs/packet_conn.hpp"
#include "hy2/obfs/salamander.hpp"

using namespace hy2;         // NOLINT
using namespace hy2::crypto; // NOLINT
using namespace hy2::obfs;   // NOLINT

namespace {

constexpr const char* kAddrA = "127.0.0.1:1111";
constexpr const char* kAddrB = "127.0.0.1:2222";

std::vector<uint8_t> StrBytes(const char* s) {
    return std::vector<uint8_t>(s, s + std::strlen(s));
}

std::string ToHex(const uint8_t* p, size_t n) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        s += hex[p[i] >> 4];
        s += hex[p[i] & 0x0f];
    }
    return s;
}

template <typename Fn>
std::string ThrownMessage(Fn&& fn) {
    try {
        fn();
    } catch (const std::exception& e) {
        return e.what();
    }
    return "";
}

// ---------------------------------------------------------------------------
// In-memory packet pipe (gecko_test.go's memEnd): bidirectional, lossy.

struct MemPacket {
    std::string src;
    std::vector<uint8_t> data;
};

class MemEnd : public IPacketConn {
public:
    explicit MemEnd(std::string addr) : addr_(std::move(addr)) {}

    void PairWith(const std::shared_ptr<MemEnd>& other) { other_ = other; }

    void SetDropFn(std::function<bool(int)> fn) { dropFn_ = std::move(fn); }

    long long WriteCount() const { return writeCount_.load(); }

    bool TryPop(MemPacket& out) {
        std::lock_guard<std::mutex> lk(mu_);
        if (inbox_.empty()) return false;
        out = std::move(inbox_.front());
        inbox_.pop_front();
        return true;
    }

    void Push(MemPacket pkt) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            inbox_.push_back(std::move(pkt));
        }
        cv_.notify_all();
    }

    size_t ReadFrom(uint8_t* buf, size_t len, std::string& srcAddr) override {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait(lk, [&] { return closed_ || !inbox_.empty(); });
        if (inbox_.empty()) throw ClosedError(); // net.ErrClosed analog
        MemPacket pkt = std::move(inbox_.front());
        inbox_.pop_front();
        const size_t n = pkt.data.size() < len ? pkt.data.size() : len;
        if (n > 0 && buf != nullptr) std::memcpy(buf, pkt.data.data(), n);
        srcAddr = std::move(pkt.src);
        return n;
    }

    void WriteTo(const uint8_t* data, size_t len, const std::string&) override {
        const int idx = static_cast<int>(writeCount_.fetch_add(1));
        if (dropFn_ && dropFn_(idx)) return;
        auto other = other_.lock();
        if (!other || len == 0) return;
        MemPacket pkt{addr_, std::vector<uint8_t>(data, data + len)};
        {
            std::lock_guard<std::mutex> olk(other->mu_);
            if (other->closed_) return;
            other->inbox_.push_back(std::move(pkt));
        }
        other->cv_.notify_all();
    }

    void Close() override {
        {
            std::lock_guard<std::mutex> lk(mu_);
            closed_ = true;
        }
        cv_.notify_all();
    }

    std::string LocalAddr() const override { return addr_; }

private:
    std::string addr_;
    std::weak_ptr<MemEnd> other_;
    std::function<bool(int)> dropFn_; // set before traffic starts
    std::atomic<long long> writeCount_{0};
    mutable std::mutex mu_;
    std::condition_variable cv_;
    bool closed_ = false;
    std::deque<MemPacket> inbox_;
};

void NewMemPipe(const std::string& aAddr, const std::string& bAddr,
                std::shared_ptr<MemEnd>& a, std::shared_ptr<MemEnd>& b) {
    a = std::make_shared<MemEnd>(aAddr);
    b = std::make_shared<MemEnd>(bAddr);
    a->PairWith(b);
    b->PairWith(a);
}

// quicLong / quicShort from gecko_test.go: deterministic payloads with the
// appropriate top bit on byte 0.
std::vector<uint8_t> QuicPayload(uint8_t firstByte, int n, uint64_t seed) {
    std::vector<uint8_t> p(static_cast<size_t>(n));
    uint64_t x = seed | 1;
    for (int i = 0; i < n; i++) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        p[static_cast<size_t>(i)] =
            static_cast<uint8_t>((x * 0x2545F4914F6CDD1DULL) >> 56);
    }
    p[0] = firstByte;
    return p;
}

std::vector<uint8_t> QuicLong(int n) { return QuicPayload(0xc0, n, 1); }
std::vector<uint8_t> QuicShort(int n) { return QuicPayload(0x40, n, 2); }

bool BytesEqual(const uint8_t* got, size_t gotLen, const std::vector<uint8_t>& want) {
    return gotLen == want.size() &&
           (want.empty() || std::memcmp(got, want.data(), want.size()) == 0);
}

void CheckBytesEqual(const uint8_t* got, size_t gotLen,
                     const std::vector<uint8_t>& want) {
    if (!BytesEqual(got, gotLen, want)) {
        std::ostringstream os;
        os << "payload mismatch: got " << gotLen << " bytes, want " << want.size()
           << " bytes";
        throw std::runtime_error(os.str());
    }
}

GeckoOptions DefaultGeckoOptions(const char* password) {
    GeckoOptions opts;
    opts.password = StrBytes(password);
    return opts;
}

} // namespace

// ---------------------------------------------------------------------------
// BLAKE2b known-answer vectors (RFC 7693 / golang.org/x/crypto/blake2b).

HY_TEST(Blake2bSum256EmptyVector) {
    Digest256 d = Blake2bSum256(nullptr, 0);
    HY_CHECK_EQ(ToHex(d.b, sizeof(d.b)),
                std::string("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"));
}

HY_TEST(Blake2bSum256AbcVector) {
    const std::vector<uint8_t> abc = {'a', 'b', 'c'};
    Digest256 d = Blake2bSum256(abc.data(), abc.size());
    HY_CHECK_EQ(ToHex(d.b, sizeof(d.b)),
                std::string("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"));
}

// ---------------------------------------------------------------------------
// salamander_test.go

HY_TEST(SalamanderObfuscator) {
    const std::vector<uint8_t> psk = StrBytes("average_password");
    SalamanderObfuscator o(psk);

    std::vector<uint8_t> in(1200);
    std::vector<uint8_t> oOut(static_cast<size_t>(kUDPBufferSize));
    std::vector<uint8_t> dOut(static_cast<size_t>(kUDPBufferSize));
    for (int iter = 0; iter < 1000; iter++) {
        RandomBytes(in.data(), in.size());
        int n = o.Obfuscate(in.data(), 1200, oOut.data(), oOut.size());
        HY_CHECK_EQ(n, 1200 + kSmSaltLen);
        n = o.Deobfuscate(oOut.data(), static_cast<size_t>(n), dOut.data(), dOut.size());
        HY_CHECK_EQ(n, 1200);
        CheckBytesEqual(dOut.data(), static_cast<size_t>(n), in);
    }
}

HY_TEST(SalamanderShortPSKRejected) {
    const std::vector<uint8_t> psk = StrBytes("abc");
    HY_CHECK_EQ(ThrownMessage([&] {
                    SalamanderObfuscator o(psk);
                    (void)o;
                }),
                std::string("PSK must be at least 4 bytes"));

    auto conn = std::make_shared<MemEnd>("127.0.0.1:1");
    HY_CHECK_EQ(ThrownMessage([&] { WrapPacketConnSalamander(conn, psk); }),
                std::string("PSK must be at least 4 bytes"));
}

HY_TEST(SalamanderInvalidDeobfuscateReturnsZero) {
    SalamanderObfuscator o(StrBytes("average_password"));
    std::vector<uint8_t> in(static_cast<size_t>(kUDPBufferSize));
    std::vector<uint8_t> out(static_cast<size_t>(kUDPBufferSize));
    RandomBytes(in.data(), in.size());

    // Input shorter than the salt (and exactly the salt) -> 0.
    HY_CHECK_EQ(o.Deobfuscate(in.data(), 7, out.data(), out.size()), 0);
    HY_CHECK_EQ(o.Deobfuscate(in.data(), kSmSaltLen, out.data(), out.size()), 0);

    // Output buffer smaller than needed -> 0.
    int n = o.Obfuscate(in.data(), 100, out.data(), out.size());
    HY_CHECK_EQ(n, 100 + kSmSaltLen);
    HY_CHECK_EQ(o.Deobfuscate(out.data(), static_cast<size_t>(n), in.data(),
                              static_cast<size_t>(n) - kSmSaltLen - 1),
                0);
    // Adequate output succeeds.
    HY_CHECK_EQ(o.Deobfuscate(out.data(), static_cast<size_t>(n), in.data(), in.size()),
                100);

    // Obfuscate into too-small output -> 0.
    HY_CHECK_EQ(o.Obfuscate(in.data(), 2048, out.data(), 2048), 0);
}

// ---------------------------------------------------------------------------
// conn.go semantics through the wrapper.

HY_TEST(WrapPacketConnSalamanderRoundtrip) {
    std::shared_ptr<MemEnd> a, b;
    NewMemPipe(kAddrA, kAddrB, a, b);
    auto wa = WrapPacketConnSalamander(a, StrBytes("average_password"));
    auto wb = WrapPacketConnSalamander(b, StrBytes("average_password"));

    std::vector<uint8_t> payload(static_cast<size_t>(400));
    RandomBytes(payload.data(), payload.size());
    wa->WriteTo(payload.data(), payload.size(), kAddrB);

    // Exactly one wire datagram, salt-prefixed (+8).
    HY_CHECK_EQ(a->WriteCount(), 1LL);
    MemPacket wire;
    HY_CHECK(b->TryPop(wire));
    HY_CHECK_EQ(wire.data.size(), payload.size() + static_cast<size_t>(kSmSaltLen));

    // Put it back so wb can receive it.
    b->Push(std::move(wire));

    std::vector<uint8_t> buf(static_cast<size_t>(4096));
    std::string src;
    size_t n = wb->ReadFrom(buf.data(), buf.size(), src);
    CheckBytesEqual(buf.data(), n, payload);
    HY_CHECK(src == kAddrA);
}

// ---------------------------------------------------------------------------
// gecko_frame_test.go

HY_TEST(FrameEncodeDecodeRoundtrip) {
    const std::vector<uint8_t> payload = {0xa1, 0xb2, 0xc3, 0xd4};
    for (uint8_t total = kGeckoMinFragmentChunks; total <= kGeckoMaxFragmentChunks;
         total++) {
        for (uint8_t idx = 0; idx < total; idx++) {
            for (int padLen : {0, 1, 64, 127, 512, 1100}) {
                FrameHeader h;
                h.padLen = static_cast<uint16_t>(padLen);
                h.msgID = 0xa5;
                h.chunkIdx = idx;
                h.totalChunks = total;
                std::vector<uint8_t> out(static_cast<size_t>(kGeckoHeaderSize) +
                                         static_cast<size_t>(padLen) + payload.size());
                const size_t n =
                    EncodeFrame(h, payload.data(), payload.size(), out.data(), out.size());
                if (n != out.size()) {
                    std::ostringstream os;
                    os << "encode wrote " << n << ", want " << out.size()
                       << " (total=" << static_cast<int>(total)
                       << " idx=" << static_cast<int>(idx) << " padLen=" << padLen << ")";
                    throw std::runtime_error(os.str());
                }
                DecodedFrame f = DecodeFrame(out.data(), out.size());
                if (!(f.header == h)) {
                    throw std::runtime_error("header mismatch");
                }
                CheckBytesEqual(f.payload, f.payloadLen, payload);
            }
        }
    }
}

HY_TEST(FrameEncodeRejectsInvalid) {
    const std::vector<uint8_t> payload = {0xff};
    std::vector<uint8_t> out(1024);

    struct Case {
        const char* name;
        FrameHeader h;
    };
    const Case cases[] = {
        {"totalChunks zero", FrameHeader{0, 0, 0, 0}},
        {"totalChunks one", FrameHeader{0, 0, 0, 1}},
        {"totalChunks nine", FrameHeader{0, 0, 0, 9}},
        {"chunkIdx out of range", FrameHeader{0, 0, 4, 4}},
    };
    for (const auto& tc : cases) {
        const std::string got =
            ThrownMessage([&] {
                EncodeFrame(tc.h, payload.data(), payload.size(), out.data(),
                            out.size());
            });
        if (got != "gecko frame invalid") {
            std::ostringstream os;
            os << tc.name << ": got \"" << got << "\", want \"gecko frame invalid\"";
            throw std::runtime_error(os.str());
        }
    }
}

HY_TEST(FrameEncodeRejectsShortBuffer) {
    const std::vector<uint8_t> payload = {0x01, 0x02, 0x03};
    FrameHeader h{8, 0, 0, 2}; // padLen=8, chunkIdx=0, totalChunks=2
    std::vector<uint8_t> out(static_cast<size_t>(kGeckoHeaderSize)); // need 5+8+3=16
    HY_CHECK_EQ(ThrownMessage([&] {
                    EncodeFrame(h, payload.data(), payload.size(), out.data(), out.size());
                }),
                std::string("gecko frame truncated"));
}

HY_TEST(FrameDecodeRejectsInvalid) {
    struct Case {
        const char* name;
        std::vector<uint8_t> in;
        const char* err;
    };
    const Case cases[] = {
        {"empty", {}, "gecko frame truncated"},
        {"header truncated", {0x80, 0x55, 0x22, 0x00}, "gecko frame truncated"},
        {"not a fragment", {0x00, 0x00, 0x22, 0x00, 0x00}, "gecko frame invalid"},
        {"totalChunks zero", {0x80, 0x00, 0x00, 0x00, 0x00}, "gecko frame invalid"},
        {"totalChunks one", {0x80, 0x00, 0x01, 0x00, 0x00}, "gecko frame invalid"},
        {"totalChunks nine", {0x80, 0x00, 0x09, 0x00, 0x00}, "gecko frame invalid"},
        {"chunkIdx == totalChunks", {0x80, 0x00, 0x44, 0x00, 0x00},
         "gecko frame invalid"},
        {"padLen overrun", {0x80, 0x00, 0x02, 0x00, 0x12, 0x01, 0x02},
         "gecko frame truncated"},
    };
    for (const auto& tc : cases) {
        const std::string got = ThrownMessage(
            [&] { DecodeFrame(tc.in.data(), tc.in.size()); });
        if (got != tc.err) {
            std::ostringstream os;
            os << tc.name << ": got \"" << got << "\", want \"" << tc.err << "\"";
            throw std::runtime_error(os.str());
        }
    }
}

// ---------------------------------------------------------------------------
// gecko_test.go

HY_TEST(GeckoRoundTripShortHeader) {
    std::shared_ptr<MemEnd> a, b;
    NewMemPipe(kAddrA, kAddrB, a, b);
    auto ga = WrapPacketConnGecko(a, DefaultGeckoOptions("test"));
    auto gb = WrapPacketConnGecko(b, DefaultGeckoOptions("test"));

    std::vector<uint8_t> payload = QuicShort(400);
    ga->WriteTo(payload.data(), payload.size(), kAddrB);
    // Short-header packets should produce exactly one wire datagram.
    HY_CHECK_EQ(a->WriteCount(), 1LL);

    std::vector<uint8_t> buf(static_cast<size_t>(4096));
    std::string src;
    size_t n = gb->ReadFrom(buf.data(), buf.size(), src);
    CheckBytesEqual(buf.data(), n, payload);
    HY_CHECK(src == kAddrA);

    ga->Close();
    gb->Close();
}

HY_TEST(GeckoRoundTripLongHeader) {
    std::shared_ptr<MemEnd> a, b;
    NewMemPipe(kAddrA, kAddrB, a, b);
    auto ga = WrapPacketConnGecko(a, DefaultGeckoOptions("test"));
    auto gb = WrapPacketConnGecko(b, DefaultGeckoOptions("test"));

    std::vector<uint8_t> payload = QuicLong(1200);
    ga->WriteTo(payload.data(), payload.size(), kAddrB);
    const long long chunks = a->WriteCount();
    HY_CHECK(chunks >= kGeckoMinFragmentChunks && chunks <= kGeckoMaxFragmentChunks);

    std::vector<uint8_t> buf(static_cast<size_t>(4096));
    std::string src;
    size_t n = gb->ReadFrom(buf.data(), buf.size(), src);
    CheckBytesEqual(buf.data(), n, payload);
    HY_CHECK(src == kAddrA);

    ga->Close();
    gb->Close();
}

HY_TEST(GeckoReassemblesOutOfOrder) {
    std::shared_ptr<MemEnd> a, b;
    NewMemPipe(kAddrA, kAddrB, a, b);
    auto ga = WrapPacketConnGecko(a, DefaultGeckoOptions("test"));

    std::vector<uint8_t> payload = QuicLong(900);
    ga->WriteTo(payload.data(), payload.size(), kAddrB);

    // Capture the raw wire datagrams from b's inbox.
    std::vector<MemPacket> pkts;
    MemPacket pkt;
    while (static_cast<long long>(pkts.size()) < a->WriteCount() && b->TryPop(pkt)) {
        pkts.push_back(std::move(pkt));
    }
    HY_CHECK_EQ(static_cast<long long>(pkts.size()), a->WriteCount());

    // Feed them to another receiver's pipe in reverse order.
    std::shared_ptr<MemEnd> c, d;
    NewMemPipe(kAddrA, kAddrB, c, d);
    auto gd = WrapPacketConnGecko(d, DefaultGeckoOptions("test"));
    for (auto it = pkts.rbegin(); it != pkts.rend(); ++it) {
        d->Push(*it);
    }

    std::vector<uint8_t> buf(static_cast<size_t>(4096));
    std::string src;
    size_t n = gd->ReadFrom(buf.data(), buf.size(), src);
    CheckBytesEqual(buf.data(), n, payload);

    ga->Close();
    gd->Close();
    c->Close();
}

HY_TEST(GeckoSmallLongHeaderRoundTrip) {
    for (int size : {1, 2, 5, 10, 15, 20, 25, 27, 30, 40, 64, 128}) {
        std::shared_ptr<MemEnd> a, b;
        NewMemPipe(kAddrA, kAddrB, a, b);
        auto ga = WrapPacketConnGecko(a, DefaultGeckoOptions("test"));
        auto gb = WrapPacketConnGecko(b, DefaultGeckoOptions("test"));

        std::vector<uint8_t> payload = QuicLong(size);
        ga->WriteTo(payload.data(), payload.size(), kAddrB);

        std::vector<uint8_t> buf(static_cast<size_t>(4096));
        std::string src;
        size_t n = gb->ReadFrom(buf.data(), buf.size(), src);
        CheckBytesEqual(buf.data(), n, payload);
        HY_CHECK_EQ(static_cast<int>(n), size);

        ga->Close();
        gb->Close();
    }
}

HY_TEST(GeckoOptionValidation) {
    // Password required.
    HY_CHECK_EQ(ThrownMessage([] {
                    GeckoOptions opts;
                    WrapPacketConnGecko(nullptr, opts);
                }),
                std::string("gecko: password is required"));

    auto conn = std::make_shared<MemEnd>("127.0.0.1:1");

    GeckoOptions minGtMax = DefaultGeckoOptions("x");
    minGtMax.minPacketSize = 1000;
    minGtMax.maxPacketSize = 500;
    HY_CHECK_EQ(ThrownMessage([&] { WrapPacketConnGecko(conn, minGtMax); }),
                std::string("gecko: invalid min/max packet size"));

    GeckoOptions negativeMin = DefaultGeckoOptions("x");
    negativeMin.minPacketSize = -1;
    HY_CHECK_EQ(ThrownMessage([&] { WrapPacketConnGecko(conn, negativeMin); }),
                std::string("gecko: invalid min/max packet size"));

    GeckoOptions maxTooBig = DefaultGeckoOptions("x");
    maxTooBig.maxPacketSize = kGeckoBufferSize + 1;
    HY_CHECK_EQ(ThrownMessage([&] { WrapPacketConnGecko(conn, maxTooBig); }),
                std::string("gecko: invalid min/max packet size"));
}
