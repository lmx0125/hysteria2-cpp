// gecko.hpp - Port of extras/obfs/gecko_frame.go and gecko.go.
// Gecko adds shape obfuscation on top of Salamander: QUIC long-header
// (handshake) packets are fragmented into randomly-sized, randomly-padded
// chunks; short-header packets pass through untouched.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "hy2/common.hpp"
#include "hy2/error.hpp"
#include "hy2/obfs/packet_conn.hpp"

namespace hy2::obfs {

// --- Frame constants (gecko_frame.go) ---
constexpr uint8_t kGeckoFlagFragment = 0x80;
constexpr int kGeckoHeaderSize = 5;
constexpr uint8_t kGeckoMinFragmentChunks = 2;
constexpr uint8_t kGeckoMaxFragmentChunks = 8;

// --- Reassembly constants (gecko.go) ---
inline constexpr Duration kGeckoReassemblyTTL = Duration::FromSeconds(8);
constexpr size_t kGeckoMaxReassembly = 4096;
constexpr size_t kGeckoMaxPerSource = 8;
constexpr size_t kGeckoBufferSize = 2048;
constexpr int kGeckoDefaultMinPacket = 512;
constexpr int kGeckoDefaultMaxPacket = 1200;

// frameHeader from gecko_frame.go. Wire layout (after Salamander decryption):
//
//	byte 0:   0x80 (fragment marker; low 7 bits reserved)
//	byte 1:   msgID
//	byte 2:   chunkIdx:4 | totalChunks:4
//	byte 3-4: padLen (uint16, big-endian)
//	then padLen random padding bytes, then the chunk payload
struct FrameHeader {
    uint16_t padLen = 0;
    uint8_t msgID = 0;
    uint8_t chunkIdx = 0;    // < totalChunks
    uint8_t totalChunks = 0; // [2, 8]

    friend bool operator==(const FrameHeader& a, const FrameHeader& b) {
        return a.padLen == b.padLen && a.msgID == b.msgID &&
               a.chunkIdx == b.chunkIdx && a.totalChunks == b.totalChunks;
    }
};

struct DecodedFrame {
    FrameHeader header;
    const uint8_t* payload = nullptr; // points into the input buffer
    size_t payloadLen = 0;
};

// Writes a frame into out, filling the padding region with random bytes.
// Returns the number of bytes written. Throws Error("gecko frame invalid")
// or Error("gecko frame truncated"). out must be at least
// kGeckoHeaderSize + h.padLen + payloadLen long.
size_t EncodeFrame(const FrameHeader& h, const uint8_t* payload, size_t payloadLen,
                   uint8_t* out, size_t outCap);

// Parses a frame from in; the returned payload aliases in. Throws
// Error("gecko frame invalid") or Error("gecko frame truncated").
DecodedFrame DecodeFrame(const uint8_t* in, size_t len);

struct GeckoOptions {
    std::vector<uint8_t> password;
    int minPacketSize = 0;
    int maxPacketSize = 0;
};

// Wraps conn with Salamander + Gecko fragmentation/reassembly.
std::shared_ptr<IPacketConn> WrapPacketConnGecko(std::shared_ptr<IPacketConn> conn,
                                                 const GeckoOptions& opts);

class GeckoPacketConn : public IPacketConn {
public:
    // inner may be null only for unit-testing internal state.
    GeckoPacketConn(std::shared_ptr<IPacketConn> inner, int minPkt, int maxPkt);
    ~GeckoPacketConn() override;

    GeckoPacketConn(const GeckoPacketConn&) = delete;
    GeckoPacketConn& operator=(const GeckoPacketConn&) = delete;

    size_t ReadFrom(uint8_t* buf, size_t len, std::string& addr) override;
    void WriteTo(const uint8_t* data, size_t len, const std::string& addr) override;
    void Close() override;
    std::string LocalAddr() const override;

private:
    struct ReassemblyKey {
        std::string addr;
        uint8_t msgID = 0;

        friend bool operator<(const ReassemblyKey& a, const ReassemblyKey& b) {
            if (a.addr != b.addr) return a.addr < b.addr;
            return a.msgID < b.msgID;
        }
    };

    struct ReassemblyEntry {
        std::vector<std::optional<std::vector<uint8_t>>> chunks;
        size_t received = 0;
        uint8_t total = 0;
        MonoTime deadline{};
    };

    void WriteFragmented(const uint8_t* p, size_t plen, const std::string& addr);
    uint16_t RandomPadLen(size_t chunkLen);
    void GcLoop();
    void GcExpired(MonoTime now);
    // Must be called with mu_ held.
    void DropEntryLocked(const ReassemblyKey& k);
    // Must be called with mu_ held. O(n) over the map; n is bounded by
    // kGeckoMaxReassembly.
    void EvictOldestLocked();
    std::optional<std::vector<uint8_t>> AcceptChunk(const std::string& addr,
                                                    const FrameHeader& h,
                                                    const uint8_t* payload,
                                                    size_t payloadLen);

    std::shared_ptr<IPacketConn> inner_;
    int minPkt_;
    int maxPkt_;

    std::atomic<uint32_t> msgID_{0};

    std::mutex readMu_;
    std::vector<uint8_t> readBuf_;

    std::mutex mu_;
    std::map<ReassemblyKey, ReassemblyEntry> reassembly_;
    std::map<std::string, int> perSource_;

    std::thread gcThread_;
    std::mutex closeMu_;
    std::condition_variable closeCv_;
    bool stop_ = false;
    std::once_flag closeOnce_;
};

} // namespace hy2::obfs
