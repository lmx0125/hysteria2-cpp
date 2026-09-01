// salamander.cpp - Port of extras/obfs/salamander.go and conn.go.
#include "hy2/obfs/salamander.hpp"

#include <cstring>
#include <utility>

#include "hy2/common.hpp"
#include "hy2/error.hpp"
#include "hy2/obfs/blake2b.hpp"

namespace hy2::obfs {

SalamanderObfuscator::SalamanderObfuscator(const std::vector<uint8_t>& psk) {
    if (psk.size() < static_cast<size_t>(kSmPSKMinLen)) {
        throw Error("PSK must be at least 4 bytes");
    }
    PSK_ = psk;
    keyInput_.resize(PSK_.size() + kSmSaltLen);
    std::memcpy(keyInput_.data(), PSK_.data(), PSK_.size());
}

std::array<uint8_t, kSmKeyLen> SalamanderObfuscator::KeyLocked(const uint8_t* salt) {
    std::memcpy(keyInput_.data() + PSK_.size(), salt, kSmSaltLen);
    crypto::Digest256 d = crypto::Blake2bSum256(keyInput_.data(), keyInput_.size());
    std::array<uint8_t, kSmKeyLen> key;
    std::memcpy(key.data(), d.b, kSmKeyLen);
    return key;
}

int SalamanderObfuscator::Obfuscate(const uint8_t* in, size_t inLen, uint8_t* out,
                                    size_t outCap) {
    const size_t outLen = inLen + kSmSaltLen;
    if (outCap < outLen) {
        return 0;
    }
    std::array<uint8_t, kSmKeyLen> key;
    {
        std::lock_guard<std::mutex> guard(lk_);
        RandomBytes(out, kSmSaltLen);
        key = KeyLocked(out);
    }
    // XOR with repeating 32-byte key. Process 8 bytes at a time when aligned.
    const uint64_t* key64 = reinterpret_cast<const uint64_t*>(key.data());
    uint64_t* out64 = reinterpret_cast<uint64_t*>(out + kSmSaltLen);
    size_t i = 0;
    // Process 8 bytes at a time (key repeats every 32 bytes = 4 uint64_t)
    for (; i + 8 <= inLen; i += 8) {
        size_t ki = (i / 8) % 4; // key offset in uint64_t units (32 bytes / 8 = 4)
        const uint64_t* in64_alias = reinterpret_cast<const uint64_t*>(in + i);
        out64[i / 8] = in64_alias[0] ^ key64[ki];
    }
    // Handle remaining bytes
    for (; i < inLen; i++) {
        out[i + kSmSaltLen] = in[i] ^ key[i % kSmKeyLen];
    }
    return static_cast<int>(outLen);
}

int SalamanderObfuscator::Deobfuscate(const uint8_t* in, size_t inLen, uint8_t* out,
                                      size_t outCap) {
    const size_t outLen = inLen - kSmSaltLen;
    if (inLen <= kSmSaltLen || outCap < outLen) {
        return 0;
    }
    std::array<uint8_t, kSmKeyLen> key;
    {
        std::lock_guard<std::mutex> guard(lk_);
        key = KeyLocked(in);
    }
    // XOR with repeating 32-byte key. Process 8 bytes at a time when aligned.
    const uint64_t* key64 = reinterpret_cast<const uint64_t*>(key.data());
    const uint64_t* in64 = reinterpret_cast<const uint64_t*>(in + kSmSaltLen);
    uint64_t* out64 = reinterpret_cast<uint64_t*>(out);
    size_t i = 0;
    for (; i + 8 <= outLen; i += 8) {
        size_t ki = (i / 8) % 4;
        out64[i / 8] = in64[i / 8] ^ key64[ki];
    }
    for (; i < outLen; i++) {
        out[i] = in[i + kSmSaltLen] ^ key[i % kSmKeyLen];
    }
    return static_cast<int>(outLen);
}

namespace {

// obfsPacketConn from conn.go.
class ObfsPacketConn : public IPacketConn {
public:
    ObfsPacketConn(std::shared_ptr<IPacketConn> conn, std::shared_ptr<IObfuscator> ob)
        : conn_(std::move(conn)),
          obfs_(std::move(ob)),
          readBuf_(kUDPBufferSize),
          writeBuf_(kUDPBufferSize) {}

    size_t ReadFrom(uint8_t* buf, size_t len, std::string& addr) override {
        for (;;) {
            size_t n;
            {
                std::lock_guard<std::mutex> guard(readMu_);
                n = conn_->ReadFrom(readBuf_.data(), readBuf_.size(), addr);
                if (n == 0) {
                    return 0;
                }
                n = static_cast<size_t>(
                    obfs_->Deobfuscate(readBuf_.data(), n, buf, len));
            }
            if (n > 0) {
                return n;
            }
            // Invalid packet, try again.
        }
    }

    void WriteTo(const uint8_t* data, size_t len, const std::string& addr) override {
        size_t nn;
        {
            std::lock_guard<std::mutex> guard(writeMu_);
            nn = static_cast<size_t>(
                obfs_->Obfuscate(data, len, writeBuf_.data(), writeBuf_.size()));
            conn_->WriteTo(writeBuf_.data(), nn, addr);
        }
        // On success the caller effectively wrote len bytes (Go returns
        // n = len(p)); errors propagate as exceptions from inner WriteTo.
    }

    void Close() override { conn_->Close(); }

    std::string LocalAddr() const override { return conn_->LocalAddr(); }

private:
    std::shared_ptr<IPacketConn> conn_;
    std::shared_ptr<IObfuscator> obfs_;
    std::vector<uint8_t> readBuf_;
    std::vector<uint8_t> writeBuf_;
    std::mutex readMu_;
    std::mutex writeMu_;
};

} // namespace

std::shared_ptr<IPacketConn> WrapPacketConnSalamander(std::shared_ptr<IPacketConn> conn,
                                                      const std::vector<uint8_t>& psk) {
    auto ob = std::make_shared<SalamanderObfuscator>(psk);
    return std::make_shared<ObfsPacketConn>(std::move(conn), std::move(ob));
}

} // namespace hy2::obfs
