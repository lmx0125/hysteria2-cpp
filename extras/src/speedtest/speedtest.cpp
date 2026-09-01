// speedtest.cpp - rewrite of extras/outbounds/speedtest/protocol.go.
#include "hy2/speedtest/speedtest.hpp"

#include "hy2/error.hpp"

namespace hy2::speedtest {

namespace {

uint32_t readUint32BE(IByteReader& r) {
    uint8_t buf[4];
    ReadFull(r, buf, 4);
    return (static_cast<uint32_t>(buf[0]) << 24) | (static_cast<uint32_t>(buf[1]) << 16) |
           (static_cast<uint32_t>(buf[2]) << 8) | static_cast<uint32_t>(buf[3]);
}

void writeUint32BE(IByteWriter& w, uint32_t v) {
    uint8_t buf[4] = {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16),
                      static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
    w.Write(buf, 4);
}

uint16_t readUint16BE(IByteReader& r) {
    uint8_t buf[2];
    ReadFull(r, buf, 2);
    return static_cast<uint16_t>((static_cast<uint16_t>(buf[0]) << 8) | buf[1]);
}

void writeUint16BE(IByteWriter& w, uint16_t v) {
    uint8_t buf[2] = {static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)};
    w.Write(buf, 2);
}

TestResult readResponse(IByteReader& r) {
    uint8_t status[1];
    ReadFull(r, status, 1);
    uint16_t msgLen = readUint16BE(r);
    TestResult res;
    // No message is fine
    if (msgLen == 0) {
        res.OK = status[0] == 0;
        return res;
    }
    std::string msg(static_cast<size_t>(msgLen), '\0');
    ReadFull(r, reinterpret_cast<uint8_t*>(msg.data()), msgLen);
    res.OK = status[0] == 0;
    res.Message = std::move(msg);
    return res;
}

void writeResponse(IByteWriter& w, bool ok, const std::string& msg) {
    if (msg.size() > 0xFFFF) throw Error("message too long");
    uint8_t status = ok ? 0 : 1;
    w.Write(&status, 1);
    writeUint16BE(w, static_cast<uint16_t>(msg.size()));
    if (!msg.empty()) {
        w.Write(reinterpret_cast<const uint8_t*>(msg.data()), msg.size());
    }
}

} // namespace

// DownloadRequest
uint32_t ReadDownloadRequest(IByteReader& r) { return readUint32BE(r); }

void WriteDownloadRequest(IByteWriter& w, uint32_t length) {
    uint8_t t = TypeDownload;
    w.Write(&t, 1);
    writeUint32BE(w, length);
}

// DownloadResponse
TestResult ReadDownloadResponse(IByteReader& r) { return readResponse(r); }

void WriteDownloadResponse(IByteWriter& w, bool ok, const std::string& msg) {
    writeResponse(w, ok, msg);
}

// UploadRequest
uint32_t ReadUploadRequest(IByteReader& r) { return readUint32BE(r); }

void WriteUploadRequest(IByteWriter& w, uint32_t length) {
    uint8_t t = TypeUpload;
    w.Write(&t, 1);
    writeUint32BE(w, length);
}

// UploadResponse
TestResult ReadUploadResponse(IByteReader& r) { return readResponse(r); }

void WriteUploadResponse(IByteWriter& w, bool ok, const std::string& msg) {
    writeResponse(w, ok, msg);
}

// UploadSummary
UploadSummary ReadUploadSummary(IByteReader& r) {
    UploadSummary s;
    s.duration = Duration::FromMillis(readUint32BE(r));
    s.ReceivedLength = readUint32BE(r);
    return s;
}

void WriteUploadSummary(IByteWriter& w, Duration duration, uint32_t receivedLength) {
    writeUint32BE(w, static_cast<uint32_t>(duration.Milliseconds()));
    writeUint32BE(w, receivedLength);
}

} // namespace hy2::speedtest
