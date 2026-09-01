// salamander.hpp - Port of extras/obfs/salamander.go + conn.go.
// Per-packet length-preserving obfuscation: each packet is prefixed with an
// 8-byte random salt and XOR'd with BLAKE2b-256(PSK || salt).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "hy2/obfs/packet_conn.hpp"

namespace hy2::obfs {

constexpr int kSmPSKMinLen = 4;
constexpr int kSmSaltLen = 8;
constexpr int kSmKeyLen = 32; // blake2b.Size256
constexpr int kUDPBufferSize = 2048;

// obfuscator interface from conn.go. Both methods return the number of bytes
// written to out, or 0 if the packet is not valid / out is too short.
class IObfuscator {
public:
    virtual ~IObfuscator() = default;
    virtual int Obfuscate(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap) = 0;
    virtual int Deobfuscate(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap) = 0;
};

class SalamanderObfuscator : public IObfuscator {
public:
    // Throws hy2::Error("PSK must be at least 4 bytes") when psk is too short.
    explicit SalamanderObfuscator(const std::vector<uint8_t>& psk);

    int Obfuscate(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap) override;
    int Deobfuscate(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap) override;

private:
    std::array<uint8_t, kSmKeyLen> KeyLocked(const uint8_t* salt);

    std::vector<uint8_t> PSK_;
    mutable std::mutex lk_;
    std::vector<uint8_t> keyInput_; // reused: PSK || salt scratch buffer
};

// Wraps conn with Salamander obfuscation. On ReadFrom, packets that fail to
// deobfuscate (n <= 0) are skipped and the read loop retries, mirroring
// conn.go's obfsPacketConn.
std::shared_ptr<IPacketConn> WrapPacketConnSalamander(std::shared_ptr<IPacketConn> conn,
                                                      const std::vector<uint8_t>& psk);

} // namespace hy2::obfs
