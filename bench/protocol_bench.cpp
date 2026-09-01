// protocol_bench.cpp - Microbenchmarks for wire format serialization/parsing.
// Tests TCPRequest, TCPResponse, UDPMessage, varint encoding, and header maps.
#include "bench.hpp"

#include "hy2/protocol.hpp"
#include "hy2/varint.hpp"

#include <cstring>
#include <vector>

using namespace hy2;
using namespace hy2::proto;

// ---------------------------------------------------------------------------
// Helpers - VecStream mirrors the test pattern for WriteTCPRequest
// ---------------------------------------------------------------------------
namespace {
struct VecWriter : public IByteWriter {
    std::vector<uint8_t> data;
    void Write(const uint8_t* p, size_t n) override {
        data.insert(data.end(), p, p + n);
    }
};
} // namespace

// ---------------------------------------------------------------------------
// TCPRequest serialization (via Serialize helper)
// ---------------------------------------------------------------------------

HY_BENCH(tcp_request_serialize_short_addr, 25) {
    (void)SerializeTCPRequest("127.0.0.1:80");
}

HY_BENCH(tcp_request_serialize_medium_addr, 30) {
    (void)SerializeTCPRequest("example.com:443");
}

HY_BENCH(tcp_request_serialize_long_addr, 60) {
    (void)SerializeTCPRequest("very-long-subdomain.example.com:65535");
}

// TCPRequest serialization via Writer interface (more realistic hot path)
HY_BENCH(tcp_request_write_stream, 30) {
    for (int i = 0; i < 1000; ++i) {
        VecWriter w;
        WriteTCPRequest(w, "example.com:443");
    }
}

// ---------------------------------------------------------------------------
// TCPRequest deserialization
// ---------------------------------------------------------------------------

HY_BENCH(tcp_request_parse_short_addr, 0) {
    auto bytes = SerializeTCPRequest("127.0.0.1:80");
    // Skip the 2-byte frame type varint (0x401) as the server dispatcher does
    SliceReader r(bytes.data() + 2, bytes.size() - 2);
    for (int i = 0; i < 500; ++i) {
        SliceReader rr(bytes.data() + 2, bytes.size() - 2);
        (void)ReadTCPRequest(rr);
    }
}

HY_BENCH(tcp_request_parse_medium_addr, 0) {
    auto bytes = SerializeTCPRequest("example.com:443");
    for (int i = 0; i < 500; ++i) {
        SliceReader rr(bytes.data() + 2, bytes.size() - 2);
        (void)ReadTCPRequest(rr);
    }
}

// ---------------------------------------------------------------------------
// TCPResponse serialization
// ---------------------------------------------------------------------------

HY_BENCH(tcp_response_serialize_ok, 30) {
    (void)SerializeTCPResponse(true, "ok");
}

HY_BENCH(tcp_response_serialize_error, 40) {
    (void)SerializeTCPResponse(false, "connection refused");
}

// TCPResponse via Writer interface
HY_BENCH(tcp_response_write_stream, 30) {
    for (int i = 0; i < 1000; ++i) {
        VecWriter w;
        WriteTCPResponse(w, true, "ok");
    }
}

// ---------------------------------------------------------------------------
// TCPResponse deserialization
// ---------------------------------------------------------------------------

HY_BENCH(tcp_response_parse_ok, 0) {
    auto bytes = SerializeTCPResponse(true, "ok");
    for (int i = 0; i < 500; ++i) {
        SliceReader r(bytes.data(), bytes.size());
        (void)ReadTCPResponse(r);
    }
}

HY_BENCH(tcp_response_parse_error, 0) {
    auto bytes = SerializeTCPResponse(false, "connection refused");
    for (int i = 0; i < 500; ++i) {
        SliceReader r(bytes.data(), bytes.size());
        (void)ReadTCPResponse(r);
    }
}

// ---------------------------------------------------------------------------
// UDPMessage serialization (various payload sizes)
// ---------------------------------------------------------------------------

namespace {
UDPMessage MakeUDPMessage(size_t dataSize) {
    UDPMessage m;
    m.SessionID = 0x12345678;
    m.PacketID = 1;
    m.FragID = 0;
    m.FragCount = 1;
    m.Addr = "127.0.0.1:53";
    m.Data.resize(dataSize);
    RandomBytes(m.Data.data(), dataSize);
    return m;
}
} // namespace

HY_BENCH(udp_msg_serialize_64B, 72) {
    auto m = MakeUDPMessage(64);
    std::vector<uint8_t> buf(1200);
    m.Serialize(buf.data(), buf.size());
}

HY_BENCH(udp_msg_serialize_256B, 264) {
    auto m = MakeUDPMessage(256);
    std::vector<uint8_t> buf(1200);
    m.Serialize(buf.data(), buf.size());
}

HY_BENCH(udp_msg_serialize_512B, 520) {
    auto m = MakeUDPMessage(512);
    std::vector<uint8_t> buf(1200);
    m.Serialize(buf.data(), buf.size());
}

HY_BENCH(udp_msg_serialize_1200B, 1208) {
    auto m = MakeUDPMessage(1200);
    std::vector<uint8_t> buf(1500);
    m.Serialize(buf.data(), buf.size());
}

HY_BENCH(udp_msg_serialize_1400B, 1408) {
    auto m = MakeUDPMessage(1400);
    std::vector<uint8_t> buf(1600);
    m.Serialize(buf.data(), buf.size());
}

// ---------------------------------------------------------------------------
// UDPMessage deserialization
// ---------------------------------------------------------------------------

namespace {
std::vector<uint8_t> SerializeUDPMsg(const UDPMessage& m) {
    std::vector<uint8_t> buf(1500);
    int n = m.Serialize(buf.data(), buf.size());
    if (n < 0) return {};
    buf.resize(static_cast<size_t>(n));
    return buf;
}
} // namespace

HY_BENCH(udp_msg_parse_64B, 0) {
    auto raw = SerializeUDPMsg(MakeUDPMessage(64));
    for (int i = 0; i < 500; ++i) {
        (void)ParseUDPMessage(raw);
    }
}

HY_BENCH(udp_msg_parse_256B, 0) {
    auto raw = SerializeUDPMsg(MakeUDPMessage(256));
    for (int i = 0; i < 500; ++i) {
        (void)ParseUDPMessage(raw);
    }
}

HY_BENCH(udp_msg_parse_512B, 0) {
    auto raw = SerializeUDPMsg(MakeUDPMessage(512));
    for (int i = 0; i < 500; ++i) {
        (void)ParseUDPMessage(raw);
    }
}

HY_BENCH(udp_msg_parse_1200B, 0) {
    auto raw = SerializeUDPMsg(MakeUDPMessage(1200));
    for (int i = 0; i < 500; ++i) {
        (void)ParseUDPMessage(raw);
    }
}

// ---------------------------------------------------------------------------
// UDPMessage roundtrip (serialize + parse)
// ---------------------------------------------------------------------------

HY_BENCH(udp_msg_roundtrip_64B, 72) {
    auto m = MakeUDPMessage(64);
    std::vector<uint8_t> buf(1200);
    int n = m.Serialize(buf.data(), buf.size());
    (void)ParseUDPMessage(buf.data(), static_cast<size_t>(n));
}

HY_BENCH(udp_msg_roundtrip_512B, 520) {
    auto m = MakeUDPMessage(512);
    std::vector<uint8_t> buf(1200);
    int n = m.Serialize(buf.data(), buf.size());
    (void)ParseUDPMessage(buf.data(), static_cast<size_t>(n));
}

// ---------------------------------------------------------------------------
// Varint encode/decode
// ---------------------------------------------------------------------------

HY_BENCH(varint_encode_small, 1) {
    uint8_t buf[8];
    for (int i = 0; i < 1000; ++i) {
        (void)VarintPut(buf, 63);
    }
}

HY_BENCH(varint_encode_medium, 2) {
    uint8_t buf[8];
    for (int i = 0; i < 1000; ++i) {
        (void)VarintPut(buf, 16383);
    }
}

HY_BENCH(varint_encode_large, 4) {
    uint8_t buf[8];
    for (int i = 0; i < 1000; ++i) {
        (void)VarintPut(buf, 1073741823);
    }
}

HY_BENCH(varint_roundtrip_small, 0) {
    uint8_t buf[8];
    for (int i = 0; i < 1000; ++i) {
        size_t n = VarintPut(buf, 63);
        size_t consumed = 0;
        (void)VarintParse(buf, n, &consumed);
    }
}

// ---------------------------------------------------------------------------
// Auth header map serialization
// ---------------------------------------------------------------------------

HY_BENCH(auth_request_to_header, 0) {
    for (int i = 0; i < 100; ++i) {
        HeaderMap h;
        AuthRequestToHeader(h, {"test-password-12345", 100000000});
    }
}

HY_BENCH(auth_request_from_header, 0) {
    HeaderMap h;
    AuthRequestToHeader(h, {"test-password-12345", 100000000});
    for (int i = 0; i < 100; ++i) {
        (void)AuthRequestFromHeader(h);
    }
}

HY_BENCH(auth_response_to_header, 0) {
    for (int i = 0; i < 100; ++i) {
        HeaderMap h;
        AuthResponseToHeader(h, {true, 500000000, false});
    }
}

HY_BENCH(auth_response_from_header, 0) {
    HeaderMap h;
    AuthResponseToHeader(h, {true, 500000000, false});
    for (int i = 0; i < 100; ++i) {
        (void)AuthResponseFromHeader(h);
    }
}

// ---------------------------------------------------------------------------
// Padding generation
// ---------------------------------------------------------------------------

HY_BENCH(padding_auth_request, 0) {
    Padding p = AuthRequestPadding();
    for (int i = 0; i < 100; ++i) {
        (void)p.String();
    }
}

HY_BENCH(padding_tcp_request, 0) {
    Padding p = TCPRequestPadding();
    for (int i = 0; i < 100; ++i) {
        (void)p.String();
    }
}
