// quic_initial.cpp - QUIC Initial packet decryption for UDP sniffing.
// Matches Go's extras/sniff/internal/quic/ implementation.
#include "hy2/sniff/quic_initial.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#if __has_include(<openssl/evp.h>)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#define HY2_OPENSSL_AVAILABLE 1
#else
#define HY2_OPENSSL_AVAILABLE 0
#endif

namespace hy2::sniff {

// QUIC versions (used by IsQuicInitial, no OpenSSL needed)
constexpr uint32_t kQuicVersion1 = 0x00000001;
constexpr uint32_t kQuicVersion2 = 0x6b3343cf;

#if !HY2_OPENSSL_AVAILABLE
// Stubs: OpenSSL not available, QUIC sniffing disabled
std::string SniffQuicInitialSourceAddress(const uint8_t*, size_t) { return ""; }
std::string ExtractQuicSNI(const uint8_t*, size_t) { return ""; }
#else

namespace {

// Initial salts (RFC 9000 Section 17)
constexpr uint8_t kSaltV1[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
};
constexpr uint8_t kSaltV2[20] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9
};

// Version-dependent labels
const char* kKeyLabelV1 = "quic key";
const char* kKeyLabelV2 = "quicv2 key";
const char* kIVLabelV1 = "quic iv";
const char* kIVLabelV2 = "quicv2 iv";
const char* kHPLabelV1 = "quic hp";
const char* kHPLabelV2 = "quicv2 hp";

// ---------------------------------------------------------------------------
// QUIC variable-length integer (RFC 9000 Section 16)

struct VarintResult {
    uint64_t value;
    size_t bytesRead;
};

VarintResult readVarint(const uint8_t* data, size_t len, size_t pos) {
    if (pos >= len) return {0, 0};
    uint8_t first = data[pos];
    int lenBytes = 1;
    uint64_t value = first & 0x3F;
    switch (first >> 6) {
    case 0: lenBytes = 1; break;
    case 1: lenBytes = 2; break;
    case 2: lenBytes = 4; break;
    case 3: lenBytes = 8; break;
    }
    for (int i = 1; i < lenBytes; i++) {
        if (pos + i >= len) return {0, 0};
        value = (value << 8) | data[pos + i];
    }
    return {value, static_cast<size_t>(lenBytes)};
}

// ---------------------------------------------------------------------------
// HKDF helpers using HMAC-SHA256 (RFC 5869)

// HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
bool hkdfExtract(const uint8_t* salt, size_t saltLen,
                  const uint8_t* ikm, size_t ikmLen,
                  uint8_t* prk, size_t prkLen) {
    unsigned int outLen = static_cast<unsigned int>(prkLen);
    unsigned char* result = HMAC(EVP_sha256(),
                                 salt, static_cast<int>(saltLen),
                                 ikm, ikmLen,
                                 prk, &outLen);
    return result != nullptr && outLen == prkLen;
}

// HKDF-Expand(PRK, info, L) using HMAC-SHA256
bool hkdfExpand(const uint8_t* prk, size_t prkLen,
                 const uint8_t* info, size_t infoLen,
                 uint8_t* output, size_t outputLen) {
    size_t done = 0;
    uint8_t counter = 1;
    unsigned char prev[EVP_MAX_MD_SIZE];
    unsigned int prevLen = 0;

    while (done < outputLen) {
        // Build input: prev || info || counter
        std::vector<uint8_t> input;
        if (done > 0) {
            input.insert(input.end(), prev, prev + prevLen);
        }
        if (infoLen > 0) {
            input.insert(input.end(), info, info + infoLen);
        }
        input.push_back(counter);

        unsigned int outLen = EVP_MAX_MD_SIZE;
        unsigned char* result = HMAC(EVP_sha256(),
                                     prk, static_cast<int>(prkLen),
                                     input.data(), input.size(),
                                     prev, &outLen);
        if (!result) return false;
        prevLen = outLen;

        size_t toCopy = std::min(outputLen - done, static_cast<size_t>(prevLen));
        std::memcpy(output + done, prev, toCopy);
        done += toCopy;
        counter++;
    }
    return true;
}

// HKDF-Expand-Label (TLS 1.3, RFC 8446 Section 7.1)
bool hkdfExpandLabel(const uint8_t* secret, size_t secretLen,
                      const char* label,
                      const uint8_t* context, size_t contextLen,
                      uint8_t* output, size_t outputLen) {
    // Build HKDF info: uint16(L) + uint8(len("tls13 "+label)) + "tls13 "+label + uint8(len(context)) + context
    std::string fullLabel = std::string("tls13 ") + label;
    std::vector<uint8_t> info;
    info.push_back(static_cast<uint8_t>((outputLen >> 8) & 0xFF));
    info.push_back(static_cast<uint8_t>(outputLen & 0xFF));
    info.push_back(static_cast<uint8_t>(fullLabel.size()));
    info.insert(info.end(), fullLabel.begin(), fullLabel.end());
    info.push_back(static_cast<uint8_t>(contextLen));
    if (contextLen > 0) {
        info.insert(info.end(), context, context + contextLen);
    }

    return hkdfExpand(secret, secretLen, info.data(), info.size(), output, outputLen);
}

// ---------------------------------------------------------------------------
// AES-128-GCM decryption

bool aes128gcmDecrypt(const uint8_t* key, const uint8_t* nonce,
                       const uint8_t* ciphertext, size_t ciphertextLen,
                       const uint8_t* aad, size_t aadLen,
                       uint8_t* plaintext) {
    if (ciphertextLen < 16) return false; // need at least auth tag
    size_t plainLen = ciphertextLen - 16;
    const uint8_t* tag = ciphertext + plainLen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) > 0
           && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) > 0
           && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) > 0
           && EVP_DecryptUpdate(ctx, nullptr, nullptr, aad, static_cast<int>(aadLen)) > 0;

    int outLen = 0;
    ok = ok && EVP_DecryptUpdate(ctx, plaintext, &outLen, ciphertext, static_cast<int>(plainLen)) > 0;

    // Set expected tag
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) > 0
           && EVP_DecryptFinal_ex(ctx, nullptr, &outLen) > 0;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// AES-128-ECB for header protection (single block)
bool aes128ecbEncrypt(const uint8_t* key, const uint8_t* input, uint8_t* output) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) > 0
           && EVP_CIPHER_CTX_set_padding(ctx, 0) > 0;
    int outLen = 0;
    ok = ok && EVP_EncryptUpdate(ctx, output, &outLen, input, 16) > 0;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// ---------------------------------------------------------------------------
// QUIC header parsing

struct QuicHeader {
    uint32_t version;
    const uint8_t* destConnID;
    size_t destConnIDLen;
    const uint8_t* srcConnID;
    size_t srcConnIDLen;
    size_t pnOffset; // offset to packet number
    size_t payloadOffset; // offset to encrypted payload (after pn)
};

bool parseQuicHeader(const uint8_t* data, size_t len, QuicHeader& hdr) {
    if (len < 7) return false;
    size_t pos = 0;

    uint8_t typeByte = data[pos++];
    if (!(typeByte & 0x80)) return false; // must be long header

    // Version (4 bytes)
    if (pos + 4 > len) return false;
    hdr.version = (static_cast<uint32_t>(data[pos]) << 24) |
                  (static_cast<uint32_t>(data[pos + 1]) << 16) |
                  (static_cast<uint32_t>(data[pos + 2]) << 8) |
                  static_cast<uint32_t>(data[pos + 3]);
    pos += 4;

    // Destination Connection ID
    if (pos >= len) return false;
    hdr.destConnIDLen = data[pos++];
    if (pos + hdr.destConnIDLen > len) return false;
    hdr.destConnID = data + pos;
    pos += hdr.destConnIDLen;

    // Source Connection ID
    if (pos >= len) return false;
    hdr.srcConnIDLen = data[pos++];
    if (pos + hdr.srcConnIDLen > len) return false;
    hdr.srcConnID = data + pos;
    pos += hdr.srcConnIDLen;

    // Check if this is an Initial packet
    // For v1: Initial packet type bits = 0b00 (bits 7-6 of typeByte >> 4 & 0x3)
    // For v2: Initial packet type bits = 0b01
    uint8_t typeBits = (typeByte >> 4) & 0x03;
    uint8_t expectedType = (hdr.version == kQuicVersion2) ? 0x01 : 0x00;
    if (typeBits != expectedType) return false;

    // Token (variable-length length + data)
    auto tokenLen = readVarint(data, len, pos);
    pos += tokenLen.bytesRead;
    if (tokenLen.value > 0) {
        pos += tokenLen.value;
    }

    // Packet number length and offset
    hdr.pnOffset = pos;

    // Length (variable-length)
    auto pktLen = readVarint(data, len, pos);
    pos += pktLen.bytesRead;

    // Payload offset is after the length varint
    hdr.payloadOffset = pos;

    return true;
}

// ---------------------------------------------------------------------------
// Packet number decoding (RFC 9000 Appendix A.1)

uint64_t decodePacketNumber(uint64_t largest, uint64_t truncated, int nbits) {
    uint64_t expected = largest + 1;
    uint64_t win = static_cast<uint64_t>(1) << (nbits * 8);
    uint64_t hwin = win / 2;
    uint64_t mask = win - 1;

    uint64_t candidate = (expected & ~mask) | truncated;

    if (candidate <= expected - hwin && candidate < (static_cast<uint64_t>(1) << 62) - win) {
        return candidate + win;
    } else if (candidate > expected + hwin && candidate >= win) {
        return candidate - win;
    }
    return candidate;
}

// ---------------------------------------------------------------------------
// CRYPTO frame extraction

std::vector<uint8_t> extractAndAssembleCryptoFrames(const uint8_t* data, size_t len) {
    struct CryptoFrame {
        uint64_t offset;
        std::vector<uint8_t> frameData;
    };
    std::vector<CryptoFrame> frames;

    size_t pos = 0;
    while (pos < len) {
        auto frameType = readVarint(data, len, pos);
        pos += frameType.bytesRead;

        if (frameType.value == 0x00) continue; // PADDING
        if (frameType.value == 0x01) continue; // PING
        if (frameType.value != 0x06) {
            // Not a CRYPTO frame, skip the rest
            break;
        }

        auto offset = readVarint(data, len, pos);
        pos += offset.bytesRead;
        auto dataLen = readVarint(data, len, pos);
        pos += dataLen.bytesRead;

        if (dataLen.value > 256 * 1024) break; // sanity limit
        if (pos + dataLen.value > len) break;

        CryptoFrame f;
        f.offset = offset.value;
        f.frameData.assign(data + pos, data + pos + dataLen.value);
        frames.push_back(std::move(f));

        pos += dataLen.value;
    }

    if (frames.empty()) return {};

    if (frames.size() == 1) {
        return std::move(frames[0].frameData);
    }

    // Sort by offset
    std::sort(frames.begin(), frames.end(),
              [](const CryptoFrame& a, const CryptoFrame& b) { return a.offset < b.offset; });

    // Find total size
    uint64_t totalSize = frames.back().offset + frames.back().frameData.size();
    if (totalSize > 256 * 1024) return {};

    std::vector<uint8_t> result(static_cast<size_t>(totalSize), 0);
    for (const auto& f : frames) {
        std::copy(f.frameData.begin(), f.frameData.end(),
                  result.begin() + static_cast<ptrdiff_t>(f.offset));
    }
    return result;
}

// ---------------------------------------------------------------------------
// TLS ClientHello SNI extraction

std::string parseClientHelloSNI(const uint8_t* data, size_t len) {
    if (len < 5) return {};
    if (data[0] != 0x01) return {}; // not ClientHello

    // Handshake length (3 bytes)
    uint32_t hsLen = (static_cast<uint32_t>(data[1]) << 16) |
                     (static_cast<uint32_t>(data[2]) << 8) |
                     static_cast<uint32_t>(data[3]);
    if (hsLen + 4 != len) return {};

    const uint8_t* b = data + 4;
    size_t pos = 0;

    // client_version (2 bytes)
    pos += 2;
    // random (32 bytes)
    pos += 32;

    if (pos >= hsLen) return {};

    // session_id
    uint8_t sessionIdLen = b[pos];
    pos += 1 + sessionIdLen;

    // cipher_suites
    if (pos + 2 > hsLen) return {};
    uint16_t cipherSuitesLen = (static_cast<uint16_t>(b[pos]) << 8) | b[pos + 1];
    pos += 2 + cipherSuitesLen;

    // compression_methods
    if (pos >= hsLen) return {};
    uint8_t compMethodsLen = b[pos];
    pos += 1 + compMethodsLen;

    // extensions
    if (pos + 2 > hsLen) return {};
    uint16_t extensionsLen = (static_cast<uint16_t>(b[pos]) << 8) | b[pos + 1];
    pos += 2;

    size_t extEnd = pos + extensionsLen;
    if (extEnd > hsLen) return {};

    while (pos + 4 <= extEnd) {
        uint16_t extType = (static_cast<uint16_t>(b[pos]) << 8) | b[pos + 1];
        uint16_t extLen = (static_cast<uint16_t>(b[pos + 2]) << 8) | b[pos + 3];
        pos += 4;

        if (pos + extLen > extEnd) break;

        if (extType == 0x0000) { // server_name
            // names list length
            if (extLen < 2) break;
            uint16_t namesLen = (static_cast<uint16_t>(b[pos]) << 8) | b[pos + 1];
            size_t sp = 2;
            while (sp + 3 <= namesLen + 2) {
                uint8_t nameType = b[pos + sp];
                uint16_t nameLen = (static_cast<uint16_t>(b[pos + sp + 1]) << 8) | b[pos + sp + 2];
                sp += 3;
                if (nameType == 0 && sp + nameLen <= namesLen + 2) {
                    std::string sni(reinterpret_cast<const char*>(b + pos + sp), nameLen);
                    // Strip trailing dot
                    if (!sni.empty() && sni.back() == '.') sni.pop_back();
                    return sni;
                }
                sp += nameLen;
            }
        }

        pos += extLen;
    }

    return {};
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API

std::string ExtractQuicSNI(const uint8_t* data, size_t len) {
    // 1. Parse header
    QuicHeader hdr{};
    if (!parseQuicHeader(data, len, hdr)) return {};
    if (hdr.version != kQuicVersion1 && hdr.version != kQuicVersion2) return {};

    // 2. Determine Initial salt
    const uint8_t* salt = (hdr.version == kQuicVersion2) ? kSaltV2 : kSaltV1;

    // 3. Key derivation
    // initialSecret = HKDF-Extract(SHA-256, ikm=destConnID, salt)
    uint8_t initialSecret[32];
    if (!hkdfExtract(salt, 20, hdr.destConnID, hdr.destConnIDLen,
                     initialSecret, 32)) return {};

    // clientSecret = HKDF-Expand-Label(secret=initialSecret, label="client in", length=32)
    uint8_t clientSecret[32];
    if (!hkdfExpandLabel(initialSecret, 32, "client in", nullptr, 0,
                         clientSecret, 32)) return {};

    // key, iv, headerKey
    const char* keyLabel = (hdr.version == kQuicVersion2) ? kKeyLabelV2 : kKeyLabelV1;
    const char* ivLabel = (hdr.version == kQuicVersion2) ? kIVLabelV2 : kIVLabelV1;
    const char* hpLabel = (hdr.version == kQuicVersion2) ? kHPLabelV2 : kHPLabelV1;

    uint8_t key[16], iv[12], headerKey[16];
    if (!hkdfExpandLabel(clientSecret, 32, keyLabel, nullptr, 0, key, 16)) return {};
    if (!hkdfExpandLabel(clientSecret, 32, ivLabel, nullptr, 0, iv, 12)) return {};
    if (!hkdfExpandLabel(clientSecret, 32, hpLabel, nullptr, 0, headerKey, 16)) return {};

    // 4. Copy packet for modification
    std::vector<uint8_t> pkt(data, data + len);

    // 5. Header protection removal
    // Sample: 16 bytes at pnOffset + 4
    size_t sampleOffset = hdr.pnOffset + 4;
    if (sampleOffset + 16 > len) return {};
    uint8_t sample[16];
    std::copy(pkt.begin() + sampleOffset, pkt.begin() + sampleOffset + 16, sample);

    // AES-128-ECB for mask
    uint8_t mask[16];
    if (!aes128ecbEncrypt(headerKey, sample, mask)) return {};

    // Remove header protection (long header: mask 4 bits of first byte)
    pkt[0] ^= mask[0] & 0x0f;

    // Determine packet number length
    int pnLen = (pkt[0] & 0x03) + 1;

    // Remove PN protection
    for (int i = 0; i < pnLen; i++) {
        pkt[hdr.pnOffset + i] ^= mask[1 + i];
    }

    // 6. Extract packet number
    uint64_t truncatedPn = 0;
    for (int i = 0; i < pnLen; i++) {
        truncatedPn = (truncatedPn << 8) | pkt[hdr.pnOffset + i];
    }
    uint64_t pn = decodePacketNumber(0, truncatedPn, pnLen); // pnMax=0 for first packet

    // 7. Build nonce: XOR(zeroPad12(pn), iv)
    uint8_t nonce[12] = {};
    nonce[4] = static_cast<uint8_t>((pn >> 56) & 0xFF);
    nonce[5] = static_cast<uint8_t>((pn >> 48) & 0xFF);
    nonce[6] = static_cast<uint8_t>((pn >> 40) & 0xFF);
    nonce[7] = static_cast<uint8_t>((pn >> 32) & 0xFF);
    nonce[8] = static_cast<uint8_t>((pn >> 24) & 0xFF);
    nonce[9] = static_cast<uint8_t>((pn >> 16) & 0xFF);
    nonce[10] = static_cast<uint8_t>((pn >> 8) & 0xFF);
    nonce[11] = static_cast<uint8_t>(pn & 0xFF);
    for (int i = 0; i < 12; i++) nonce[i] ^= iv[i];

    // 8. AEAD header (everything before the encrypted payload)
    size_t headerLen = hdr.pnOffset + pnLen;
    const uint8_t* header = pkt.data();

    // 9. Encrypted payload
    size_t payloadEnd = hdr.payloadOffset + (pkt.size() - hdr.payloadOffset);
    // Actually, the length field includes pn + encrypted payload
    // The encrypted data starts at headerLen and goes to the end
    const uint8_t* ciphertext = pkt.data() + headerLen;
    size_t ciphertextLen = pkt.size() - headerLen;

    if (ciphertextLen < 16) return {}; // need at least auth tag

    // 10. Decrypt
    std::vector<uint8_t> plaintext(ciphertextLen - 16);
    if (!aes128gcmDecrypt(key, nonce, ciphertext, ciphertextLen,
                          header, headerLen, plaintext.data())) return {};

    // 11. Extract and reassemble CRYPTO frames
    auto cryptoPayload = extractAndAssembleCryptoFrames(plaintext.data(), plaintext.size());
    if (cryptoPayload.empty()) return {};

    // 12. Parse ClientHello SNI
    return parseClientHelloSNI(cryptoPayload.data(), cryptoPayload.size());
}

bool IsQuicInitial(const uint8_t* data, size_t len) {
    if (len < 7) return false;
    if (!(data[0] & 0x80)) return false; // must be long header

    uint32_t version = (static_cast<uint32_t>(data[1]) << 24) |
                       (static_cast<uint32_t>(data[2]) << 16) |
                       (static_cast<uint32_t>(data[3]) << 8) |
                       static_cast<uint32_t>(data[4]);

    if (version != kQuicVersion1 && version != kQuicVersion2) return false;

    // Check Initial packet type bits
    uint8_t typeBits = (data[0] >> 4) & 0x03;
    uint8_t expectedType = (version == kQuicVersion2) ? 0x01 : 0x00;
    return typeBits == expectedType;
}

#endif // HY2_OPENSSL_AVAILABLE

#ifndef HY2_OPENSSL_AVAILABLE
// IsQuicInitial is a pure header parser, no OpenSSL needed
bool IsQuicInitial(const uint8_t* data, size_t len) {
    if (len < 7) return false;
    if (!(data[0] & 0x80)) return false; // must be long header

    uint32_t version = (static_cast<uint32_t>(data[1]) << 24) |
                       (static_cast<uint32_t>(data[2]) << 16) |
                       (static_cast<uint32_t>(data[3]) << 8) |
                       static_cast<uint32_t>(data[4]);

    if (version != kQuicVersion1 && version != kQuicVersion2) return false;

    // Check Initial packet type bits
    uint8_t typeBits = (data[0] >> 4) & 0x03;
    uint8_t expectedType = (version == kQuicVersion2) ? 0x01 : 0x00;
    return typeBits == expectedType;
}

#endif // !HY2_OPENSSL_AVAILABLE

} // namespace hy2::sniff
