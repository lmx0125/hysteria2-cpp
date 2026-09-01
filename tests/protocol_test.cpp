// protocol_test.cpp - Wire format tests for varint + TCPRequest/TCPResponse/
// UDPMessage framing. Vectors are derived from the Go implementation's
// documented encoding (QUIC RFC 9000 varints, big-endian fields).
#include "hytest.hpp"

#include <cstring>
#include <sstream>

#include "hy2/error.hpp"
#include "hy2/protocol.hpp"
#include "hy2/varint.hpp"

using namespace hy2;
using namespace hy2::proto;

// ---------------------------------------------------------------------------
// Varint (mirrors quicvarint tests)

HY_TEST(VarintLengths)
{
    HY_CHECK_EQ(VarintLen(0), (size_t)1);
    HY_CHECK_EQ(VarintLen(63), (size_t)1);
    HY_CHECK_EQ(VarintLen(64), (size_t)2);
    HY_CHECK_EQ(VarintLen(16383), (size_t)2);
    HY_CHECK_EQ(VarintLen(16384), (size_t)4);
    HY_CHECK_EQ(VarintLen(1073741823), (size_t)4);
    HY_CHECK_EQ(VarintLen(1073741824), (size_t)8);
    HY_CHECK_EQ(VarintLen(4611686018427387903ULL), (size_t)8);
}

HY_TEST(VarintRoundtrip)
{
    const uint64_t values[] = {
        0, 1, 62, 63, 64, 1000, 16383, 16384, 65535,
        1073741823ULL, 1073741824ULL, 4611686018427387903ULL,
    };
    for (uint64_t v : values) {
        uint8_t buf[8] = {};
        size_t n = VarintPut(buf, v);
        HY_CHECK_EQ(n, VarintLen(v));
        size_t consumed = 0;
        auto parsed = VarintParse(buf, n, &consumed);
        HY_CHECK(parsed.has_value());
        HY_CHECK_EQ(*parsed, v);
        HY_CHECK_EQ(consumed, n);

        // stream read
        SliceReader r(buf, n);
        HY_CHECK_EQ(VarintRead(r), v);
    }
}

HY_TEST(VarintKnownEncodings)
{
    // RFC 9000 Appendix A vectors
    {
        uint8_t buf[1];
        HY_CHECK_EQ(VarintPut(buf, 0), (size_t)1);
        HY_CHECK(buf[0] == 0x00);
    }
    {
        uint8_t buf[1];
        VarintPut(buf, 63);
        HY_CHECK(buf[0] == 0x3f);
    }
    {
        uint8_t buf[2];
        HY_CHECK_EQ(VarintPut(buf, 15293), (size_t)2);
        HY_CHECK(buf[0] == 0x7b && buf[1] == 0xbd);
    }
    {
        uint8_t buf[4];
        HY_CHECK_EQ(VarintPut(buf, 494878333), (size_t)4);
        HY_CHECK(buf[0] == 0x9d && buf[1] == 0x7f && buf[2] == 0x3e && buf[3] == 0x7d);
    }
    {
        uint8_t buf[8];
        HY_CHECK_EQ(VarintPut(buf, 151288809941952652ULL), (size_t)8);
        HY_CHECK(buf[0] == 0xc2 && buf[1] == 0x19 && buf[2] == 0x7c && buf[3] == 0x5e &&
                 buf[4] == 0xff && buf[5] == 0x14 && buf[6] == 0xe8 && buf[7] == 0x8c);
    }
}

HY_TEST(VarintTruncatedParse)
{
    uint8_t buf[8];
    VarintPut(buf, 494878333); // needs 4 bytes
    for (size_t i = 0; i < 3; i++) {
        auto v = VarintParse(buf, i);
        HY_CHECK(!v.has_value());
    }
    // stream read throws on truncation
    SliceReader r(buf, 2);
    bool threw = false;
    try {
        VarintRead(r);
    } catch (const Error&) {
        threw = true;
    }
    HY_CHECK(threw);
}

// ---------------------------------------------------------------------------
// TCPRequest / TCPResponse

namespace {
// Deterministic reader over a full buffer
struct VecStream : public IByteReaderWriter {
    std::vector<uint8_t> data;
    size_t pos = 0;

    size_t Read(uint8_t* p, size_t n) override {
        if (pos >= data.size()) return 0;
        size_t got = std::min(n, data.size() - pos);
        std::memcpy(p, data.data() + pos, got);
        pos += got;
        return got;
    }
    void Write(const uint8_t* p, size_t n) override {
        data.insert(data.end(), p, p + n);
    }
};
} // namespace

HY_TEST(TCPRequestRoundtrip)
{
    VecStream s;
    WriteTCPRequest(s, "example.com:443");
    HY_CHECK(!s.data.empty());

    // First byte(s): frame type 0x401 as 2-byte QUIC varint:
    // b0 = 0x40 | (0x401 >> 8) = 0x44, b1 = 0x01
    HY_CHECK_EQ(s.data[0], (uint8_t)0x44);
    HY_CHECK_EQ(s.data[1], (uint8_t)0x01);

    // ReadTCPRequest expects to start after the frame-type varint
    // (the stream dispatcher already consumed it).
    SliceReader r(s.data.data() + 2, s.data.size() - 2);
    std::string addr = ReadTCPRequest(r);
    HY_CHECK_EQ(addr, std::string("example.com:443"));
}

HY_TEST(TCPRequestRejectsBadAddrLen)
{
    // ReadTCPRequest starts at the address length (frame type already
    // consumed by the stream dispatcher).
    // addr length = 0 => ProtocolError
    std::vector<uint8_t> buf;
    VarintAppend(buf, 0);
    SliceReader r(buf.data(), buf.size());
    HY_CHECK_THROWS(ReadTCPRequest(r), ProtocolError);

    // addr length > MaxAddressLength => ProtocolError
    buf.clear();
    VarintAppend(buf, kMaxAddressLength + 1);
    new (&r) SliceReader(buf.data(), buf.size());
    HY_CHECK_THROWS(ReadTCPRequest(r), ProtocolError);
}

HY_TEST(TCPResponseRoundtrip)
{
    VecStream s;
    WriteTCPResponse(s, true, "Connected");
    HY_CHECK_EQ(s.data[0], (uint8_t)0); // status ok

    SliceReader r(s.data.data(), s.data.size());
    auto resp = ReadTCPResponse(r);
    HY_CHECK(resp.OK);
    HY_CHECK_EQ(resp.Message, std::string("Connected"));

    VecStream s2;
    WriteTCPResponse(s2, false, "no route to host");
    HY_CHECK_EQ(s2.data[0], (uint8_t)1); // status error
    SliceReader r2(s2.data.data(), s2.data.size());
    auto resp2 = ReadTCPResponse(r2);
    HY_CHECK(!resp2.OK);
    HY_CHECK_EQ(resp2.Message, std::string("no route to host"));
}

HY_TEST(TCPResponseRejectsBadMsgLen)
{
    std::vector<uint8_t> buf{0x00}; // status ok
    VarintAppend(buf, (uint64_t)kMaxMessageLength + 1); // message length too big
    SliceReader r(buf.data(), buf.size());
    HY_CHECK_THROWS(ReadTCPResponse(r), ProtocolError);
}

// ---------------------------------------------------------------------------
// UDPMessage

HY_TEST(UDPMessageHeaderSizeAndSerialize)
{
    UDPMessage m;
    m.SessionID = 0x11223344;
    m.PacketID = 0x5566;
    m.FragID = 0x77;
    m.FragCount = 0x88;
    m.Addr = "1.2.3.4:53";
    m.Data = {0xde, 0xad, 0xbe, 0xef};

    // header: 8 + varintlen(10)=1 + 10 = 19
    HY_CHECK_EQ(m.HeaderSize(), (size_t)19);
    HY_CHECK_EQ(m.Size(), (size_t)23);

    std::vector<uint8_t> buf(m.Size());
    int n = m.Serialize(buf.data(), buf.size());
    HY_CHECK_EQ(n, (int)m.Size());

    const uint8_t expect[] = {
        0x11, 0x22, 0x33, 0x44, // session id BE
        0x55, 0x66,             // packet id BE
        0x77, 0x88,             // frag id, frag count
        0x0a,                   // addr len varint (10)
        '1', '.', '2', '.', '3', '.', '4', ':', '5', '3',
        0xde, 0xad, 0xbe, 0xef,
    };
    HY_CHECK_EQ(buf.size(), sizeof(expect));
    HY_CHECK(std::memcmp(buf.data(), expect, sizeof(expect)) == 0);

    auto parsed = ParseUDPMessage(buf);
    HY_CHECK_EQ(parsed.SessionID, (uint32_t)0x11223344);
    HY_CHECK_EQ(parsed.PacketID, (uint16_t)0x5566);
    HY_CHECK_EQ(parsed.FragID, (uint8_t)0x77);
    HY_CHECK_EQ(parsed.FragCount, (uint8_t)0x88);
    HY_CHECK_EQ(parsed.Addr, std::string("1.2.3.4:53"));
    HY_CHECK(parsed.Data == std::vector<uint8_t>({0xde, 0xad, 0xbe, 0xef}));
}

HY_TEST(UDPMessageSerializeTooSmall)
{
    UDPMessage m;
    m.SessionID = 1;
    m.Addr = "abcd";
    m.Data = {1, 2, 3};
    std::vector<uint8_t> small(4);
    HY_CHECK_EQ(m.Serialize(small.data(), small.size()), -1);
}

HY_TEST(ParseUDPMessageInvalid)
{
    // empty
    HY_CHECK_THROWS(ParseUDPMessage(std::vector<uint8_t>{}), Error);

    // only 7 bytes (truncated before fragcount... actually < 8 header bytes)
    HY_CHECK_THROWS(ParseUDPMessage(std::vector<uint8_t>{1, 2, 3, 4, 5, 6, 7}), Error);

    // zero-length address => invalid address length
    {
        std::vector<uint8_t> buf{0, 0, 0, 1, 0, 0, 0, 1, 0x00};
        HY_CHECK_THROWS(ParseUDPMessage(buf), ProtocolError);
    }

    // address length > MaxMessageLength
    {
        std::vector<uint8_t> buf{0, 0, 0, 1, 0, 0, 0, 1};
        VarintAppend(buf, (uint64_t)kMaxMessageLength + 1);
        HY_CHECK_THROWS(ParseUDPMessage(buf), ProtocolError);
    }

    // no data after address (<= comparison) => invalid message length
    {
        std::string addr = "ab";
        std::vector<uint8_t> buf{0, 0, 0, 1, 0, 0, 0, 1};
        VarintAppend(buf, (uint64_t)addr.size());
        for (char c : addr) buf.push_back((uint8_t)c);
        HY_CHECK_THROWS(ParseUDPMessage(buf), ProtocolError);
    }
}

HY_TEST(PaddingRanges)
{
    // Padding lengths fall into [Min, Max) and use [a-zA-Z0-9]
    auto checkPadding = [](const Padding& p, int min, int max) {
        for (int i = 0; i < 50; i++) {
            std::string s = p.String();
            HY_CHECK((int)s.size() >= min && (int)s.size() < max);
            for (char c : s) {
                HY_CHECK((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                         (c >= '0' && c <= '9'));
            }
        }
    };
    checkPadding(AuthRequestPadding(), 256, 2048);
    checkPadding(AuthResponsePadding(), 256, 2048);
    checkPadding(TCPRequestPadding(), 64, 512);
    checkPadding(TCPResponsePadding(), 128, 1024);
}

HY_TEST(AuthHeadersRoundtrip)
{
    HeaderMap h;
    AuthRequestToHeader(h, AuthRequest{"secret123", 54321});
    HY_CHECK_EQ(h[std::string(RequestHeaderAuth)], std::string("secret123"));
    HY_CHECK_EQ(h[std::string(CommonHeaderCCRX)], std::string("54321"));
    HY_CHECK(h.count(CommonHeaderPadding) == 1);

    AuthRequest req = AuthRequestFromHeader(h);
    HY_CHECK_EQ(req.Auth, std::string("secret123"));
    HY_CHECK_EQ(req.Rx, (uint64_t)54321);

    HeaderMap h2;
    AuthResponseToHeader(h2, AuthResponse{true, 999999, false});
    HY_CHECK_EQ(h2[std::string(ResponseHeaderUDPEnabled)], std::string("true"));
    HY_CHECK_EQ(h2[std::string(CommonHeaderCCRX)], std::string("999999"));
    AuthResponse resp = AuthResponseFromHeader(h2);
    HY_CHECK(resp.UDPEnabled);
    HY_CHECK(!resp.RxAuto);
    HY_CHECK_EQ(resp.Rx, (uint64_t)999999);

    HeaderMap h3;
    AuthResponseToHeader(h3, AuthResponse{false, 0, true});
    HY_CHECK_EQ(h3[std::string(CommonHeaderCCRX)], std::string("auto"));
    AuthResponse resp3 = AuthResponseFromHeader(h3);
    HY_CHECK(resp3.RxAuto);
    HY_CHECK(!resp3.UDPEnabled);
}
