#if HY2_WITH_QUIC_BACKEND
#include "hy2/h3/hy_server.hpp"

#include <algorithm>

#ifdef _WIN32
#include <winsock2.h>
#endif

namespace hy2::h3sess {

HyServer::HyServer(const HyServerParams& params,
                   server::Authenticator* auth, server::Outbound* outbound)
    : params_(params), auth_(auth), outbound_(outbound) {
    quic_backend::Ngtcp2Listener::ServerParams sp;
    sp.bindAddr = params_.bindAddr;
    sp.port = params_.port;
    sp.certChainPEM = {params_.certPem};
    sp.privateKeyPEM = {params_.keyPem};
    sp.datagramEnabled = true;

    listener_ = quic_backend::Ngtcp2Listener::Create(sp);
    if (!listener_) {
#ifdef _WIN32
        int errCode = WSAGetLastError();
#else
        int errCode = errno;
#endif
        throw std::runtime_error("hy2 server: listener create failed (err=" +
                                 std::to_string(errCode) + ")");
    }
    port_ = listener_->GetSocketRaw()->LocalPort();

    acceptThread_ = std::thread(&HyServer::AcceptLoop, this);
}

HyServer::~HyServer() { Stop(); }

void HyServer::AcceptLoop() {
    while (!stop_) {
        std::shared_ptr<IQuicConnection> conn;
        try {
            conn = listener_->Accept();
        } catch (...) {
            break;
        }
        if (!conn) break;

        auto session = std::shared_ptr<HySession>(
            new HySession(conn, auth_, outbound_, params_.udpEnabled));
        {
            std::lock_guard<std::mutex> lk(reg_->mu);
            reg_->list.push_back(session);
        }

        // Auth + serve on a worker thread; drop session when done. The
        // registry is captured by shared_ptr: even if this HyServer dies
        // first, the finishing worker can safely inspect/erase its entry.
        std::thread([reg = reg_, session] {
            if (session->Auth()) {
                session->Serve();
            } else {
                session->Stop();
            }
            std::lock_guard<std::mutex> lk(reg->mu);
            reg->list.erase(
                std::remove_if(reg->list.begin(), reg->list.end(),
                               [&](const std::shared_ptr<HySession>& p) {
                                   return p.get() == session.get();
                               }),
                reg->list.end());
        }).detach();
    }
}

void HyServer::Stop() {
    if (stop_.exchange(true)) return;
    if (listener_) listener_->Close();
    {
        std::lock_guard<std::mutex> lk(reg_->mu);
        for (auto& s : reg_->list) s->Stop();
        reg_->list.clear();
    }
    if (acceptThread_.joinable()) acceptThread_.join();
}

} // namespace hy2::h3sess

#endif // HY2_WITH_QUIC_BACKEND


