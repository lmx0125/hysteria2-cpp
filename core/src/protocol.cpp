// protocol.cpp - Wire protocol implementation (rewrite of proxy.go/padding.go/http.go).
#include "hy2/protocol.hpp"

#include <cassert>
#include <mutex>
#include <random>

#include "hy2/error.hpp"
#include "hy2/varint.hpp"

namespace hy2::proto {

// ---------------------------------------------------------------------------
// Padding

namespace {
const char kPaddingChars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

std::mt19937_64& Rng() {
    // 64-bit engine seeded with the full 64-bit random value (no entropy loss).
    thread_local std::mt19937_64 rng{RandomUint64()};
    return rng;
}
} // namespace

std::string Padding::String() const {
    int range = Max - Min;
    int n = Min;
    if (range > 0) n = Min + static_cast<int>(Rng()() % static_cast<uint32_t>(range));
    std::string s(static_cast<size_t>(n), '\0');
    constexpr size_t charsLen = sizeof(kPaddingChars) - 1; // 62
    auto& rng = Rng();
    for (int i = 0; i < n; i++) {
        s[i] = kPaddingChars[rng() % charsLen];
    }
    return s;
}

Padding AuthRequestPadding() { return Padding{256, 2048}; }
Padding AuthResponsePadding() { return Padding{256, 2048}; }
Padding TCPRequestPadding() { return Padding{64, 512}; }
Padding TCPResponsePadding() { return Padding{128, 1024}; }

// ---------------------------------------------------------------------------
// TCPRequest

std::string ReadTCPRequest(IByteReader& r) {
    // Starts at the address length: the frame-type varint (0x401) was
    // already consumed by the stream dispatcher/hijacker (matches Go).
    uint64_t addrLen = VarintRead(r);
    if (addrLen == 0 || addrLen > kMaxAddressLength) {
        throw ProtocolError("invalid address length");
    }
    std::string addr;
    addr.resize(static_cast<size_t>(addrLen));
    ReadFull(r, reinterpret_cast<uint8_t*>(addr.data()), static_cast<size_t>(addrLen));
    uint64_t paddingLen = VarintRead(r);
    if (paddingLen > kMaxPaddingLength) {
        throw ProtocolError("invalid padding length");
    }
    if (paddingLen > 0) {
        DiscardN(r, static_cast<size_t>(paddingLen));
    }
    return addr;
}

std::vector<uint8_t> SerializeTCPRequest(const std::string& addr) {
    std::string padding = TCPRequestPadding().String();
    size_t paddingLen = padding.size();
    size_t addrLen = addr.size();
    size_t sz = VarintLen(FrameTypeTCPRequest) +
                VarintLen(addrLen) + addrLen +
                VarintLen(paddingLen) + paddingLen;
    std::vector<uint8_t> buf(sz);
    size_t i = VarintPut(buf.data(), FrameTypeTCPRequest);
    i += VarintPut(buf.data() + i, addrLen);
    std::copy(addr.begin(), addr.end(), buf.begin() + static_cast<long>(i));
    i += addrLen;
    i += VarintPut(buf.data() + i, paddingLen);
    std::copy(padding.begin(), padding.end(), buf.begin() + static_cast<long>(i));
    return buf;
}

void WriteTCPRequest(IByteWriter& w, const std::string& addr) {
    auto buf = SerializeTCPRequest(addr);
    w.Write(buf.data(), buf.size());
}

// ---------------------------------------------------------------------------
// TCPResponse

TCPResponseResult ReadTCPResponse(IByteReader& r) {
    uint8_t status[1];
    ReadFull(r, status, 1);
    uint64_t msgLen = VarintRead(r);
    if (msgLen > kMaxMessageLength) {
        throw ProtocolError("invalid message length");
    }
    std::string msg;
    // No message is fine
    if (msgLen > 0) {
        msg.resize(static_cast<size_t>(msgLen));
        ReadFull(r, reinterpret_cast<uint8_t*>(msg.data()), static_cast<size_t>(msgLen));
    }
    uint64_t paddingLen = VarintRead(r);
    if (paddingLen > kMaxPaddingLength) {
        throw ProtocolError("invalid padding length");
    }
    if (paddingLen > 0) {
        DiscardN(r, static_cast<size_t>(paddingLen));
    }
    return TCPResponseResult{status[0] == 0, msg};
}

std::vector<uint8_t> SerializeTCPResponse(bool ok, const std::string& msg) {
    std::string padding = TCPResponsePadding().String();
    size_t paddingLen = padding.size();
    size_t msgLen = msg.size();
    size_t sz = 1 + VarintLen(msgLen) + msgLen + VarintLen(paddingLen) + paddingLen;
    std::vector<uint8_t> buf(sz);
    buf[0] = ok ? 0 : 1;
    size_t pos = 1;
    pos += VarintPut(buf.data() + pos, msgLen);
    std::copy(msg.begin(), msg.end(), buf.begin() + static_cast<long>(pos));
    pos += msgLen;
    pos += VarintPut(buf.data() + pos, paddingLen);
    std::copy(padding.begin(), padding.end(), buf.begin() + static_cast<long>(pos));
    return buf;
}

void WriteTCPResponse(IByteWriter& w, bool ok, const std::string& msg) {
    auto buf = SerializeTCPResponse(ok, msg);
    w.Write(buf.data(), buf.size());
}

// ---------------------------------------------------------------------------
// UDPMessage

size_t UDPMessage::HeaderSize() const {
    size_t lAddr = Addr.size();
    return 4 + 2 + 1 + 1 + VarintLen(lAddr) + lAddr;
}

int UDPMessage::Serialize(uint8_t* buf, size_t bufLen) const {
    // Make sure the buffer is big enough
    if (bufLen < Size()) {
        return -1;
    }
    buf[0] = static_cast<uint8_t>(SessionID >> 24);
    buf[1] = static_cast<uint8_t>(SessionID >> 16);
    buf[2] = static_cast<uint8_t>(SessionID >> 8);
    buf[3] = static_cast<uint8_t>(SessionID);
    buf[4] = static_cast<uint8_t>(PacketID >> 8);
    buf[5] = static_cast<uint8_t>(PacketID);
    buf[6] = FragID;
    buf[7] = FragCount;
    size_t i = VarintPut(buf + 8, Addr.size());
    std::copy(Addr.begin(), Addr.end(), buf + 8 + i);
    i += Addr.size();
    if (!Data.empty()) {
        std::copy(Data.begin(), Data.end(), buf + 8 + i);
    }
    return static_cast<int>(8 + i + Data.size());
}

UDPMessage ParseUDPMessage(const uint8_t* msg, size_t len) {
    UDPMessage m;
    ParseUDPMessageInPlace(m, msg, len);
    return m;
}

void ParseUDPMessageInPlace(UDPMessage& m, const uint8_t* msg, size_t len) {
    if (len < 8) {
        throw Error("unexpected EOF");
    }
    m.SessionID = (static_cast<uint32_t>(msg[0]) << 24) | (static_cast<uint32_t>(msg[1]) << 16) |
                  (static_cast<uint32_t>(msg[2]) << 8) | static_cast<uint32_t>(msg[3]);
    m.PacketID = static_cast<uint16_t>((static_cast<uint16_t>(msg[4]) << 8) | msg[5]);
    m.FragID = msg[6];
    m.FragCount = msg[7];
    size_t consumed = 0;
    auto lAddrOpt = VarintParse(msg + 8, len - 8, &consumed);
    if (!lAddrOpt) {
        throw Error("unexpected EOF");
    }
    uint64_t lAddr = *lAddrOpt;
    if (lAddr == 0 || lAddr > kMaxMessageLength) {
        throw ProtocolError("invalid address length");
    }
    if (len - 8 - consumed <= lAddr) {
        throw ProtocolError("invalid message length");
    }
    // Reuse existing string buffer — assign() may reuse capacity if large enough
    m.Addr.assign(reinterpret_cast<const char*>(msg + 8 + consumed), static_cast<size_t>(lAddr));
    // Reuse existing vector buffer — assign() may reuse capacity if large enough
    m.Data.assign(msg + 8 + consumed + lAddr, msg + len);
}

// ---------------------------------------------------------------------------
// HTTP auth headers

AuthRequest AuthRequestFromHeader(const HeaderMap& h) {
    AuthRequest req;
    // Case-insensitive header lookup (HTTP/3 headers are case-insensitive)
    auto findCi = [&h](const std::string& key) -> HeaderMap::const_iterator {
        for (auto it = h.begin(); it != h.end(); ++it) {
            if (it->first.size() == key.size() &&
                std::equal(it->first.begin(), it->first.end(), key.begin(),
                           [](char a, char b) { return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); })) {
                return it;
            }
        }
        return h.end();
    };
    auto itAuth = findCi(RequestHeaderAuth);
    if (itAuth != h.end()) req.Auth = itAuth->second;
    uint64_t rx = 0;
    auto itRx = findCi(CommonHeaderCCRX);
    if (itRx != h.end()) {
        try {
            size_t pos = 0;
            unsigned long long v = std::stoull(itRx->second, &pos);
            if (pos == itRx->second.size()) rx = v;
        } catch (...) {
            rx = 0;
        }
    }
    req.Rx = rx;
    return req;
}

void AuthRequestToHeader(HeaderMap& h, const AuthRequest& req) {
    h[RequestHeaderAuth] = req.Auth;
    h[CommonHeaderCCRX] = std::to_string(req.Rx);
    h[CommonHeaderPadding] = AuthRequestPadding().String();
}

AuthResponse AuthResponseFromHeader(const HeaderMap& h) {
    AuthResponse resp;
    // Case-insensitive header lookup (HTTP/3 headers are case-insensitive)
    auto findCi = [&h](const std::string& key) -> HeaderMap::const_iterator {
        for (auto it = h.begin(); it != h.end(); ++it) {
            if (it->first.size() == key.size() &&
                std::equal(it->first.begin(), it->first.end(), key.begin(),
                           [](char a, char b) { return std::tolower((unsigned char)a) == std::tolower((unsigned char)b); })) {
                return it;
            }
        }
        return h.end();
    };
    auto itUdp = findCi(ResponseHeaderUDPEnabled);
    if (itUdp != h.end()) {
        resp.UDPEnabled = (itUdp->second == "1" || itUdp->second == "t" || itUdp->second == "T" ||
                           itUdp->second == "true" || itUdp->second == "TRUE" || itUdp->second == "True");
    }
    auto itRx = findCi(CommonHeaderCCRX);
    if (itRx != h.end()) {
        const std::string& rxStr = itRx->second;
        if (rxStr == "auto") {
            // Special case for server requesting client to use bandwidth detection
            resp.RxAuto = true;
        } else {
            try {
                size_t pos = 0;
                unsigned long long v = std::stoull(rxStr, &pos);
                if (pos == rxStr.size()) resp.Rx = v;
            } catch (...) {
                resp.Rx = 0;
            }
        }
    }
    return resp;
}

void AuthResponseToHeader(HeaderMap& h, const AuthResponse& resp) {
    h[ResponseHeaderUDPEnabled] = resp.UDPEnabled ? "true" : "false";
    if (resp.RxAuto) {
        h[CommonHeaderCCRX] = "auto";
    } else {
        h[CommonHeaderCCRX] = std::to_string(resp.Rx);
    }
    h[CommonHeaderPadding] = AuthResponsePadding().String();
}

} // namespace hy2::proto
