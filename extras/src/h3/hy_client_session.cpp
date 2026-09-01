#include "hy2/h3/hy_client_session.hpp"

#include <chrono>
#include <thread>
#include <stdexcept>

#include "hy2/h3/h3.hpp"
#include "hy2/common.hpp"
#include "hy2/error.hpp"

namespace hy2::h3sess {

using namespace hy2::h3;
using namespace hy2::proto;

HyClient::HyClient(std::shared_ptr<IQuicConnection> conn, std::string auth)
    : conn_(std::move(conn)), auth_(std::move(auth)) {
    // Drain peer HTTP/3 control / QPACK unidirectional streams so their
    // flow control doesn't stall the connection.
    drainThread_ = std::thread([conn = conn_] {
        for (;;) {
            auto st = conn->AcceptUniStream();
            if (!st) return;
            std::thread([st] {
                uint8_t sink[4096];
                try {
                    for (;;) {
                        size_t n = st->Read(sink, sizeof(sink));
                        if (n == 0) return;
                    }
                } catch (...) {}
            }).detach();
        }
    });
}

HyClient::~HyClient() { Close(); }

void HyClient::Close() {
    bool expected = false;
    if (!closed_.compare_exchange_strong(expected, true)) return;
    if (conn_) {
        try { conn_->CloseWithError(0x100, ""); } catch (...) {}
    }
    if (drainThread_.joinable()) {
        try { drainThread_.join(); } catch (...) {}
    }
}

void HyClient::Auth() {
    AuthRequest areq;
    areq.Auth = auth_;
    areq.Rx = 0; // let the server decide (BBR on both ends)

    HeaderMap hm;
    AuthRequestToHeader(hm, areq);
    Padding pad = AuthRequestPadding();
    // Overwrite padding with a deterministic-ish value? Official sends random;
    // keep generated one from map (AuthRequestToHeader sets CC-RX + padding).
    (void)pad;

    std::vector<Header> headers;
    for (auto& kv : hm) headers.emplace_back(kv.first, kv.second);

    auto resp = Request(*conn_, "POST", URLHost, URLPath, headers);

    if (resp.StatusCode != StatusAuthOK) {
        throw std::runtime_error("auth error: status " +
                                 std::to_string(resp.StatusCode));
    }

    HeaderMap rh;
    for (auto& h : resp.Headers) rh[h.first] = h.second;
    AuthResponse aresp = AuthResponseFromHeader(rh);
    udpEnabled_ = aresp.UDPEnabled;
}

std::shared_ptr<IQuicStream> HyClient::TCP(const std::string& addr,
                                           std::string* errMsg) {
    auto st = conn_->OpenStream();
    auto bytes = SerializeTCPRequest(addr);
    st->Write(bytes.data(), bytes.size());

    TCPResponseResult resp;
    try {
        resp = ReadTCPResponse(*st);
    } catch (const std::exception& e) {
        if (errMsg) *errMsg = e.what();
        try { st->Close(); } catch (...) {}
        return nullptr;
    }
    if (!resp.OK) {
        if (errMsg) *errMsg = resp.Message;
        try { st->Close(); } catch (...) {}
        return nullptr;
    }
    return st;
}

void HyClient::UDPSend(uint32_t sessionID, const std::string& addr,
                       const uint8_t* data, size_t n) {
    UDPMessage msg;
    msg.SessionID = sessionID;
    msg.PacketID = 0;
    msg.FragID = 0;
    msg.FragCount = 1;
    msg.Addr = addr;
    msg.Data.assign(data, data + n);

    // Buffer sized for the largest possible message; fragments reuse it.
    std::vector<uint8_t> buf(kMaxUDPSize);
    auto sendWhole = [&](const UDPMessage& m) {
        int wn = m.Serialize(buf.data(), buf.size());
        if (wn <= 0) throw Error("udp message serialize failed");
        conn_->SendDatagram(buf.data(), static_cast<size_t>(wn));
    };

    try {
        sendWhole(msg); // may throw DatagramTooLargeError
    } catch (const DatagramTooLargeError& e) {
        // Too large for one datagram: fragment like Go's UdpConn.Send.
        msg.PacketID = static_cast<uint16_t>(RandomUint64() % 0xFFFF) + 1;
        auto frags = frag::FragUDPMessage(msg,
                                          static_cast<size_t>(e.MaxDatagramPayloadSize));
        for (const auto& f : frags) {
            sendWhole(f);
        }
    }
}

proto::UDPMessage HyClient::UDPReceive() {
    for (;;) {
        std::vector<uint8_t> d = conn_->ReceiveDatagram();
        try {
            auto dfMsg = udpDefrag_.Feed(ParseUDPMessage(d));
            if (!dfMsg) continue; // incomplete fragment set - wait for more
            return *dfMsg;
        } catch (...) {
            continue; // invalid - wait for next
        }
    }
}

} // namespace hy2::h3sess

