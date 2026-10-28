// qstream.hpp - QStream wrapper. Rewrite of core/internal/utils/qstream.go.
//
// QStream wraps an IQuicStream so that Close() cancels pending reads
// (CancelRead(0)) before closing the write side.
#pragma once

#include "hy2/quic.hpp"

namespace hy2 {

class QStream : public IHyStream {
public:
    explicit QStream(std::shared_ptr<IQuicStream> stream) : stream_(std::move(stream)) {}

    uint64_t StreamID() const override { return stream_->StreamID(); }

    size_t Read(uint8_t* p, size_t n) override { return stream_->Read(p, n); }
    void Write(const uint8_t* p, size_t n) override { stream_->Write(p, n); }

    void Close() override {
        stream_->CancelRead(StreamErrorCode(0));
        stream_->Close();
    }
    void CloseWrite() override { stream_->CloseWrite(); }

    void CancelRead(StreamErrorCode code) override { stream_->CancelRead(code); }
    void CancelWrite(StreamErrorCode code) override { stream_->CancelWrite(code); }
    void SetReadDeadline(MonoTime t) override { stream_->SetReadDeadline(t); }
    void SetWriteDeadline(MonoTime t) override { stream_->SetWriteDeadline(t); }
    void SetDeadline(MonoTime t) override { stream_->SetDeadline(t); }

private:
    std::shared_ptr<IQuicStream> stream_;
};

} // namespace hy2
