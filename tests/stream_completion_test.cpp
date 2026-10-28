#include "hytest.hpp"
#include "hy2_quic_test_util.hpp"

#ifdef HY2_WITH_QUIC_BACKEND
#include "hy2/quic_backend/ngtcp2_listener.hpp"
#include "hy2/quic_backend/quic_backend_factory.hpp"
#include "hy2/qstream.hpp"
#include <vector>
#include <chrono>
#include <thread>

namespace {
struct CompletionPair {
    std::shared_ptr<hy2::quic_backend::Ngtcp2Listener> listener;
    std::shared_ptr<hy2::IQuicConnection> client, server;
    explicit CompletionPair(bool defaults = false) {
        hy2::quic_backend::Ngtcp2Listener::ServerParams sp;
        sp.bindAddr = "127.0.0.1";
        sp.port = 0;
        sp.certChainPEM = {hy2test::kTestCertPem};
        sp.privateKeyPEM = {hy2test::kTestKeyPem};
        listener = hy2::quic_backend::Ngtcp2Listener::Create(sp);
        hy2::QuicConfig cfg;
        if (!defaults) {
            cfg.DisableChromeParrot = true;
            cfg.InitialConnectionReceiveWindow = 512 * 1024;
            cfg.InitialStreamReceiveWindow = 256 * 1024;
        }
        client = hy2::quic_backend::CreateQuicConnection(
            "127.0.0.1:" + std::to_string(listener->GetSocketRaw()->LocalPort()),
            "localhost", cfg, true);
        server = listener->Accept();
    }
    ~CompletionPair() {
        if (client) client->CloseWithError(0, "test done");
        if (server) server->CloseWithError(0, "test done");
        if (listener) listener->Close();
    }
};

void CompletedResponses(bool defaults, bool separateFin) {
    CompletionPair pair(defaults);
    const std::vector<uint8_t> data((defaults ? 240 : 64) * 1024, 0x5a);
    std::vector<uint8_t> buf(data.size());
    const size_t count = defaults ? 72 : 12;
    for (size_t i = 0; i < count; ++i) {
        auto raw = pair.client->OpenStream();
        hy2::QStream c(raw);
        const uint8_t request = 1;
        c.Write(&request, 1);
        auto s = pair.server->AcceptStream();
        s->SetReadDeadline(hy2::MonoTime::Now().Add(2000000000LL));
        HY_CHECK_EQ(s->Read(buf.data(), 1), size_t{1});
        s->Write(data.data(), data.size());
        if (!separateFin) s->Close();
        c.SetReadDeadline(hy2::MonoTime::Now().Add(2000000000LL));
        size_t got = 0;
        while (got < data.size()) {
            size_t n = c.Read(buf.data() + got, buf.size() - got);
            if (!n) break;
            got += n;
        }
        HY_CHECK_EQ(got, data.size());
        HY_CHECK(buf == data);
        if (separateFin) s->Close();
        HY_CHECK_EQ(c.Read(buf.data(), 1), size_t{0});
        c.Close();
        c.Close(); // repeated close must not return the tail twice
    }
}
}

HY_TEST(StreamCompletion_ShortResponsesKeepConnectionCredit) {
    CompletedResponses(false, false);
}
HY_TEST(StreamCompletion_DefaultWindowShortResponses) {
    CompletedResponses(true, false);
}
HY_TEST(StreamCompletion_SeparateFinFlushesConsumedTail) {
    CompletedResponses(false, true);
}
HY_TEST(StreamCompletion_CloseWritePreservesResponse) {
    CompletionPair pair;
    hy2::QStream c(pair.client->OpenStream());
    const uint8_t upload[] = {1,2,3,4};
    c.Write(upload, sizeof(upload));
    c.CloseWrite();
    auto s = pair.server->AcceptStream();
    s->SetReadDeadline(hy2::MonoTime::Now().Add(2000000000LL));
    uint8_t buf[4];
    hy2::ReadFull(*s, buf, sizeof(buf));
    HY_CHECK(std::equal(std::begin(buf), std::end(buf), std::begin(upload)));
    HY_CHECK_EQ(s->Read(buf, sizeof(buf)), size_t{0});
    s->Write(upload, sizeof(upload));
    s->Close();
    c.SetReadDeadline(hy2::MonoTime::Now().Add(2000000000LL));
    hy2::ReadFull(c, buf, sizeof(buf));
    HY_CHECK(std::equal(std::begin(buf), std::end(buf), std::begin(upload)));
    HY_CHECK_EQ(c.Read(buf, sizeof(buf)), size_t{0});
    c.Close();
}
HY_TEST(StreamCompletion_FinishedUnreadResponsesReturnCredit) {
    CompletionPair pair;
    const std::vector<uint8_t> data(64 * 1024, 0x5a);
    for (int i = 0; i < 12; ++i) {
        hy2::QStream c(pair.client->OpenStream());
        uint8_t byte = 1;
        c.Write(&byte, 1);
        c.CloseWrite();
        auto s = pair.server->AcceptStream();
        s->SetReadDeadline(hy2::MonoTime::Now().Add(2000000000LL));
        HY_CHECK_EQ(s->Read(&byte, 1), size_t{1});
        s->Write(data.data(), data.size());
        s->Close();
        c.SetReadDeadline(hy2::MonoTime::Now().Add(2000000000LL));
        HY_CHECK_EQ(c.Read(&byte, 1), size_t{1});
        // Both FINs have completed at transport level, while the application
        // deliberately leaves almost the whole response unread. This tests
        // CancelRead's peer-FIN branch independently of Read's EOF flush.
        const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (pair.client->GetStatsSnapshot().streamsOpen != 0 &&
               std::chrono::steady_clock::now() < end) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        HY_CHECK_EQ(pair.client->GetStatsSnapshot().streamsOpen, uint64_t{0});
        c.Close();
        c.Close();
    }
}
#endif
