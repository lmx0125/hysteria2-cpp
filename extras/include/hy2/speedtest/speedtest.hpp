// speedtest.hpp - Rewrite of extras/outbounds/speedtest/protocol.go (framing
// only; client.go/server.go need real connections and are omitted).
// All multi-byte integers are big-endian on the wire.
#pragma once

#include <cstdint>
#include <string>

#include "hy2/common.hpp"
#include "hy2/io.hpp"

namespace hy2::speedtest {

constexpr uint8_t TypeDownload = 0x1;
constexpr uint8_t TypeUpload = 0x2;

// DownloadRequest format:
// 0x1 (byte)
// Request data length (uint32 BE)
uint32_t ReadDownloadRequest(IByteReader& r);
void WriteDownloadRequest(IByteWriter& w, uint32_t length);

// DownloadResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (uint16 BE)
// Message (bytes)
struct TestResult {
    bool OK = false;
    std::string Message;
};
TestResult ReadDownloadResponse(IByteReader& r);
void WriteDownloadResponse(IByteWriter& w, bool ok, const std::string& msg);

// UploadRequest format:
// 0x2 (byte)
// Upload data length (uint32 BE)
uint32_t ReadUploadRequest(IByteReader& r);
void WriteUploadRequest(IByteWriter& w, uint32_t length);

// UploadResponse format: same as DownloadResponse.
TestResult ReadUploadResponse(IByteReader& r);
void WriteUploadResponse(IByteWriter& w, bool ok, const std::string& msg);

// UploadSummary format:
// Duration (in milliseconds, uint32 BE)
// Received data length (uint32 BE)
struct UploadSummary {
    Duration duration{};
    uint32_t ReceivedLength = 0;
};
UploadSummary ReadUploadSummary(IByteReader& r);
void WriteUploadSummary(IByteWriter& w, Duration duration, uint32_t receivedLength);

} // namespace hy2::speedtest
