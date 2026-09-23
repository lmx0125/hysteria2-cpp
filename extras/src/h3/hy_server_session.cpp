#include "hy2/h3/hy_server_session.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "hy2/h3/h3.hpp"
#include "hy2/congestion_factory.hpp"
#include "hy2/copy.hpp"
#include "hy2/error.hpp"
#include "hy2/varint.hpp"
#include "hy2/server_udp.hpp"

namespace hy2::h3sess {

using namespace hy2::h3;
using namespace hy2::proto;
using namespace hy2::server;

namespace {

class NopUdpEventLogger : public UdpEventLogger {
    void New(uint32_t, const std::string&) override {}
    void Close(uint32_t, const std::string&) override {}
};

// Bridges the real QUIC connection + outbound to the core UdpSessionManager
// (mirrors Go's udpIOImpl in server.go).
class HyUdpIOImpl : public UdpIO {
public:
    std::shared_ptr<IQuicConnection> conn;
    Outbound* outbound = nullptr;

    std::shared_ptr<proto::UDPMessage> ReceiveMessage() override {
        auto v = conn->ReceiveDatagram(); // throws when the connection closes
        return std::make_shared<proto::UDPMessage>(ParseUDPMessage(v));
    }
    void SendMessage(uint8_t* buf, size_t bufLen,
                     const proto::UDPMessage& msg) override {
        int n = msg.Serialize(buf, bufLen);
        if (n < 0) throw Error("udp message serialize failed");
        conn->SendDatagram(buf, static_cast<size_t>(n));
    }
    void Hook(std::vector<uint8_t>&, std::string&) override {}
    std::shared_ptr<IUdpConn> UDP(const std::string& reqAddr) override {
        return outbound ? outbound->UDP(reqAddr) : nullptr;
    }
    bool CheckUDP(const std::string& reqAddr) override {
        return outbound ? outbound->CheckUDP(reqAddr) : true;
    }
};

} // namespace

static const char* FindHeader(const std::vector<Header>& hs,
                              const std::string& name) {
    for (auto& h : hs) {
        if (h.first == name) return h.second.c_str();
    }
    return nullptr;
}

HySession::HySession(std::shared_ptr<IQuicConnection> conn,
                     Authenticator* auth, Outbound* outbound,
                     const HySessionConfig& config)
    : conn_(std::move(conn)), auth_(auth), outbound_(outbound),
      config_(config), udpEnabled_(config.udpEnabled) {}

HySession::~HySession() { Stop(); }

void HySession::Stop() {
    if (stop_.exchange(true)) return;
    if (conn_) {
        try { conn_->CloseWithError(0x100, ""); } catch (...) {}
    }
}

// ---------------------------------------------------------------------------
// Auth: first bidi stream must be HTTP/3 POST /auth.
bool HySession::Auth() {
    // Server-side control stream with SETTINGS is mandatory (RFC 9114);
    // quic-go clients expect it during the exchange.
    try {
        SendControlStream(*conn_, BuildServerSettingsBody());
    } catch (...) {}

    std::shared_ptr<IQuicStream> st;
    try {
        st = conn_->AcceptStream(); // blocks until client opens auth stream
    } catch (...) {
        return false;
    }
    if (!st) return false;

    ServerRequest req;
    try {
        req = ReadRequest(*st);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[hy2-server] auth read failed: %s\n", e.what());
        return false;
    }

    if (req.Method != "POST" || req.Path != "/auth") {
        std::fprintf(stderr, "[hy2-server] not an auth request: %s %s\n",
                     req.Method.c_str(), req.Path.c_str());
        try { SendResponse(*st, 404, {}); } catch (...) {}
        return false;
    }

    HeaderMap hm;
    for (auto& h : req.Headers) {
        // HTTP field names are case-insensitive (RFC 9110 §5.1); quic-go
        // emits lowercase, our proto constants use canonical case.
        std::string lower;
        lower.reserve(h.first.size());
        for (char c : h.first) {
            lower.push_back(c >= 'A' && c <= 'Z'
                                ? static_cast<char>(c - 'A' + 'a')
                                : c);
        }
        hm[lower] = h.second;
    }
    // Normalize the constants' lookup keys to lowercase as well.
    auto lc = [](std::string s) {
        for (auto& c : s) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        return s;
    };
    AuthRequest areq;
    areq.Auth = hm[lc(proto::RequestHeaderAuth)];
    if (std::getenv("HY2_QUIC_DEBUG")) {
        for (auto& kv : req.Headers) {
            std::fprintf(stderr, "[hy2-server] hdr %s = %s\n",
                         kv.first.c_str(),
                         kv.second.substr(0, 40).c_str());
        }
        std::fprintf(stderr, "[hy2-server] method=%s path=%s auth=%s\n",
                     req.Method.c_str(), req.Path.c_str(), areq.Auth.c_str());
    }
    {
        auto it = hm.find(lc(proto::CommonHeaderCCRX));
        areq.Rx = it != hm.end() ? std::strtoull(it->second.c_str(), nullptr, 10) : 0;
    }
    std::string id;
    bool ok = auth_ && auth_->Authenticate(req.Authority, areq.Auth,
                                           areq.Rx, id);
    if (std::getenv("HY2_QUIC_DEBUG")) {
        std::fprintf(stderr, "[hy2-server] auth=%s result=%s\n",
                     areq.Auth.c_str(), ok ? "OK" : "FAIL");
    }
    if (!ok) {
        try { SendResponse(*st, 401, {}); } catch (...) {}
        return false;
    }

    // Congestion / bandwidth negotiation, mirroring
    // core::server::H3sHandler::ServeHTTP:
    //   - the client's requested download rate (areq.Rx) drives OUR send
    //     congestion control (Brutal when > 0, else the configured CC),
    //   - the advertised back-pressure (aresp.Rx) lets the client use
    //     Brutal for its upload direction.
    AuthResponse aresp;
    aresp.UDPEnabled = udpEnabled_;
    aresp.Rx = 0;
    uint64_t actualTx = 0;
    if (config_.ignoreClientBandwidth) {
        hy2::cc::UseConfigured(*conn_, config_.congestionType, config_.bbrProfile);
    } else {
        actualTx = areq.Rx;
        if (config_.bandwidthMaxTx > 0 && actualTx > config_.bandwidthMaxTx) {
            actualTx = config_.bandwidthMaxTx;
        }
        if (actualTx > 0) {
            hy2::cc::UseBrutal(*conn_, actualTx, config_.disableLossCompensation);
        } else {
            hy2::cc::UseConfigured(*conn_, config_.congestionType, config_.bbrProfile);
        }
        aresp.Rx = config_.bandwidthMaxRx;
    }
    // One line per connection: useful to verify the negotiated CC without
    // enabling the (very verbose) full protocol tracing.
    if (!std::getenv("HY2_CC_SILENT")) {
        std::fprintf(stderr,
                     "[hy2-server] cc: clientRx=%llu actualTx=%llu arespRx=%llu "
                     "ignore=%d brutalRequest=%d quic=%s\n",
                     (unsigned long long)areq.Rx,
                     (unsigned long long)actualTx,
                     (unsigned long long)aresp.Rx,
                     config_.ignoreClientBandwidth ? 1 : 0,
                     actualTx > 0 ? 1 : 0,
                     config_.congestionType.c_str());
    }

    HeaderMap rh;
    AuthResponseToHeader(rh, aresp);
    (void)lc;

    std::vector<Header> respHeaders;
    for (auto& kv : rh) respHeaders.emplace_back(kv.first, kv.second);

    try {
        SendResponse(*st, StatusAuthOK, respHeaders);
    } catch (...) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// TCP proxy on one bidi stream using the exact wire framing + CopyTwoWay.
void HySession::ServeStream(std::shared_ptr<IQuicStream> st) {
    if (std::getenv("HY2_QUIC_DEBUG"))
        std::fprintf(stderr, "[hy2-server] ServeStream enter\n");
    std::string addr;
    try {
        // Consume the frame-type varint (0x401); ReadTCPRequest starts at
        // the address length.
        uint64_t ft = VarintRead(*st);
        if (ft != FrameTypeTCPRequest) {
            throw std::runtime_error("invalid tcp request frame type");
        }
        addr = ReadTCPRequest(*st);
    } catch (const std::exception& e) {
        if (std::getenv("HY2_QUIC_DEBUG"))
            std::fprintf(stderr, "[hy2-server] tcp req parse fail: %s\n",
                         e.what());
        try { st->Close(); } catch (...) {}
        return;
    }
    if (std::getenv("HY2_QUIC_DEBUG"))
        std::fprintf(stderr, "[hy2-server] TCP dial %s\n", addr.c_str());

    std::shared_ptr<IConn> remote;
    TCPResponseResult resp;
    try {
        remote = outbound_ ? outbound_->TCP(addr) : nullptr;
    } catch (const std::exception& e) {
        auto bytes = SerializeTCPResponse(false, e.what());
        try { st->Write(bytes.data(), bytes.size()); st->Close(); } catch (...) {}
        return;
    }
    if (!remote) {
        auto bytes = SerializeTCPResponse(false, "dial failed");
        try { st->Write(bytes.data(), bytes.size()); st->Close(); } catch (...) {}
        return;
    }

    auto okBytes = SerializeTCPResponse(true, "");
    try {
        if (std::getenv("HY2_DIAG")) {
            std::fprintf(stderr, "[hy2-server] writing TCP response ok (%zu bytes) to stream\n",
                         okBytes.size());
            std::fflush(stderr);
        }
        st->Write(okBytes.data(), okBytes.size());
    } catch (...) {
        return;
    }

    // Relay both directions until either side closes.
    if (std::getenv("HY2_DIAG")) {
        std::fprintf(stderr, "[hy2-server] response sent, relaying %s\n", addr.c_str());
        std::fflush(stderr);
    }
    const auto relayStart = std::chrono::steady_clock::now();
    CopyTwoWay(st, remote);
    if (std::getenv("HY2_DIAG")) {
        std::fprintf(stderr, "[hy2-server] relay %s done in %lld ms\n", addr.c_str(),
                     (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - relayStart).count());
        std::fflush(stderr);
    }

    try { st->Close(); } catch (...) {}
    if (remote) remote->Close();
}

// ---------------------------------------------------------------------------
// UDP relay: drives the core UdpSessionManager (per-SessionID NAT sessions,
// inbound defragmentation, auto-fragmenting replies) until the connection
// dies. Port of Go's h3sHandler UDP path (sm := newUDPSessionManager(...);
// go sm.Run()).
void HySession::RunUdpRelay() {
    if (!udpEnabled_ || !outbound_) return;
    if (std::getenv("HY2_QUIC_DEBUG"))
        std::fprintf(stderr, "[hy2-server] udp relay enter\n");

    auto io = std::make_shared<HyUdpIOImpl>();
    io->conn = conn_;
    io->outbound = outbound_;
    auto elog = std::make_shared<NopUdpEventLogger>();

    // Direct construction: this thread owns the manager for its lifetime and
    // keeps io/elog alive via shared_ptr, so raw pointers stay valid.
    UdpSessionManager mgr(io.get(), elog.get(), Duration::FromSeconds(60));
    try {
        mgr.Run(); // exits when ReceiveMessage throws (connection closed)
    } catch (...) {
    }
    mgr.Stop(); // join session receive loops deterministically

    if (std::getenv("HY2_QUIC_DEBUG"))
        std::fprintf(stderr, "[hy2-server] udp relay exit\n");
}

void HySession::Serve() {
    auto self = shared_from_this();
    if (std::getenv("HY2_QUIC_DEBUG"))
        std::fprintf(stderr, "[hy2-server] Serve enter\n");

    std::thread streamThread([self] {
        if (std::getenv("HY2_QUIC_DEBUG"))
            std::fprintf(stderr, "[hy2-server] streamThread enter\n");
        while (!self->stop_) {
            std::shared_ptr<IQuicStream> st;
            try {
                st = self->conn_->AcceptStream();
            } catch (...) {
                break;
            }
            if (!st) break;
            if (std::getenv("HY2_QUIC_DEBUG"))
                std::fprintf(stderr, "[hy2-server] accepted stream\n");
            std::thread(&HySession::ServeStream, self, st).detach();
        }
    });

    std::thread dgramThread([self] {
        self->RunUdpRelay();
    });

    // Drain peer HTTP/3 control / QPACK unidirectional streams. Without this
    // the peer's flow control fills up and the whole connection stalls.
    std::thread uniDrainThread([self] {
        for (;;) {
            if (self->stop_) return;
            std::shared_ptr<IQuicStream> st = self->conn_->AcceptUniStream();
            if (!st) return; // connection closed
            std::thread([st] {
                uint8_t sink[4096];
                try {
                    for (;;) {
                        size_t n = st->Read(sink, sizeof(sink));
                        if (n == 0) return; // peer FIN
                    }
                } catch (...) {}
            }).detach();
        }
    });

    if (streamThread.joinable()) streamThread.join();
    if (dgramThread.joinable()) dgramThread.join();
    // uniDrainThread exits when stop_ is set; it may block on AcceptUniStream,
    // which returns nullptr once the connection closes.
    uniDrainThread.detach();
}

} // namespace hy2::h3sess






