// frag_test.cpp - Port of core/internal/frag/frag_test.go.
#include "hytest.hpp"

#include "hy2/frag.hpp"

using namespace hy2;
using namespace hy2::frag;
using proto::UDPMessage;

namespace {
UDPMessage makeMsg(uint32_t sessionID, uint16_t packetID, const std::string& addr,
                   std::vector<uint8_t> data) {
    UDPMessage m;
    m.SessionID = sessionID;
    m.PacketID = packetID;
    m.FragID = 0;
    m.FragCount = 1;
    m.Addr = addr;
    m.Data = std::move(data);
    return m;
}

// Go test uses a 1000-byte message with addr "localhost:1234"
UDPMessage makeTestMsg(std::vector<uint8_t> data) {
    return makeMsg(5, 6, "localhost:1234", std::move(data));
}
} // namespace

HY_TEST(FragUDPMessageNoFragmentNeeded)
{
    auto data = std::vector<uint8_t>(500, 0xAB);
    auto m = makeTestMsg(data);
    auto frags = FragUDPMessage(m, 1200);
    HY_CHECK_EQ(frags.size(), (size_t)1);
    HY_CHECK_EQ(frags[0].SessionID, (uint32_t)5);
    HY_CHECK_EQ(frags[0].PacketID, (uint16_t)6);
    HY_CHECK_EQ(frags[0].FragID, (uint8_t)0);
    HY_CHECK_EQ(frags[0].FragCount, (uint8_t)1);
    HY_CHECK_EQ(frags[0].Addr, std::string("localhost:1234"));
    HY_CHECK(frags[0].Data == data);
}

HY_TEST(FragUDPMessageFragments)
{
    // Go frag_test: message of 1000 bytes with maxSize 300
    // HeaderSize = 8 + varint(len("localhost:1234")=14)=1 + 14 = 23
    // maxPayloadSize = 300 - 23 = 277; fragCount = ceil(1000/277) = 4
    auto data = std::vector<uint8_t>(1000);
    for (size_t i = 0; i < data.size(); i++) data[i] = (uint8_t)i;
    auto m = makeTestMsg(data);

    auto frags = FragUDPMessage(m, 300);
    HY_CHECK_EQ(frags.size(), (size_t)4);

    size_t off = 0;
    for (uint8_t i = 0; i < 4; i++) {
        HY_CHECK_EQ(frags[i].PacketID, (uint16_t)6);
        HY_CHECK_EQ(frags[i].FragID, i);
        HY_CHECK_EQ(frags[i].FragCount, (uint8_t)4);
        HY_CHECK_EQ(frags[i].Addr, std::string("localhost:1234"));
        size_t expected = std::min<size_t>(277, data.size() - off);
        HY_CHECK_EQ(frags[i].Data.size(), expected);
        for (size_t j = 0; j < expected; j++) {
            if (frags[i].Data[j] != data[off + j]) {
                HY_CHECK(false && "fragment payload mismatch");
            }
        }
        off += expected;
    }
    // wire sizes must not exceed maxSize
    for (const auto& f : frags) {
        HY_CHECK(f.Size() <= 300);
    }
}

HY_TEST(FragUDPMessageHeaderTooBig)
{
    auto m = makeTestMsg({1, 2, 3});
    // maxSize smaller than the header alone => no fragments possible
    auto frags = FragUDPMessage(m, 10);
    HY_CHECK(frags.empty());
}

HY_TEST(DefraggerSingleFragmentPassThrough)
{
    Defragger d;
    auto m = makeTestMsg({1, 2, 3});
    auto out = d.Feed(m);
    HY_CHECK(out != nullptr);
    HY_CHECK_EQ(out->Data.size(), (size_t)3);
}

HY_TEST(DefraggerCollectsAndAssembles)
{
    Defragger d;
    auto full = std::vector<uint8_t>(600);
    for (size_t i = 0; i < full.size(); i++) full[i] = (uint8_t)(i * 7);
    auto m = makeTestMsg(full);
    auto frags = FragUDPMessage(m, 250); // header 23 => maxPayload 227 => 3 frags

    HY_CHECK_EQ(frags.size(), (size_t)3);

    // feed out of order
    auto r2 = d.Feed(frags[2]);
    HY_CHECK(r2 == nullptr);
    auto r0 = d.Feed(frags[0]);
    HY_CHECK(r0 == nullptr);
    auto r1 = d.Feed(frags[1]);
    HY_CHECK(r1 != nullptr);
    HY_CHECK_EQ(r1->FragID, (uint8_t)0);
    HY_CHECK_EQ(r1->FragCount, (uint8_t)1);
    HY_CHECK(r1->Data == full);
    HY_CHECK_EQ(r1->Addr, std::string("localhost:1234"));
    HY_CHECK_EQ(r1->SessionID, (uint32_t)5);
}

HY_TEST(DefraggerResetsOnDifferentPacket)
{
    Defragger d;
    auto m = makeTestMsg(std::vector<uint8_t>(500));
    auto frags = FragUDPMessage(m, 250);
    HY_CHECK(frags.size() > 1);

    auto r0 = d.Feed(frags[0]);
    HY_CHECK(r0 == nullptr);

    // different packet id => previous state discarded
    auto m2 = makeTestMsg(std::vector<uint8_t>(500));
    m2.PacketID = 99;
    auto frags2 = FragUDPMessage(m2, 250);
    auto rA = d.Feed(frags2[0]);
    HY_CHECK(rA == nullptr);
    auto rB = d.Feed(frags2[1]);
    // only second fragment of new packet received -> still incomplete
    HY_CHECK(rB == nullptr);
}

HY_TEST(DefraggerRejectsBadFragID)
{
    Defragger d;
    auto m = makeTestMsg({1});
    m.FragCount = 3;
    m.FragID = 3; // >= FragCount
    auto out = d.Feed(m);
    HY_CHECK(out == nullptr);
}
