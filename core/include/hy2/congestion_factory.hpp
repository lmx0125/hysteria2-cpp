// congestion_factory.hpp - Rewrite of core/internal/congestion/utils.go.
#pragma once

#include <string>

#include "hy2/bbr.hpp"
#include "hy2/brutal.hpp"
#include "hy2/quic.hpp"

namespace hy2::cc {

constexpr const char* TypeBBR = "bbr";
constexpr const char* TypeReno = "reno";

// NormalizeType normalizes a congestion type string; throws on unsupported.
inline std::string NormalizeType(const std::string& congestionType) {
    std::string normalized;
    normalized.reserve(congestionType.size());
    for (char c : congestionType) {
        normalized.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    }
    if (normalized.empty() || normalized == TypeBBR) return TypeBBR;
    if (normalized == TypeReno) return TypeReno;
    throw Error("unsupported congestion type \"" + congestionType + "\"");
}

// NormalizeBBRProfile validates and normalizes a BBR profile name.
inline std::string NormalizeBBRProfile(const std::string& profile) {
    return bbr::ParseProfile(profile);
}

// seedPacketSize picks the datagram size to seed a replacement congestion
// controller with (see Go utils.go for rationale).
inline ByteCount SeedPacketSize(ByteCount quicSize, ByteCount byAddr) {
    if (quicSize <= 0) {
        return byAddr;
    }
    return quicSize < byAddr ? quicSize : byAddr;
}

// UseBBR attaches a BBR controller to the connection.
inline void UseBBR(IQuicConnection& conn, const bbr::Profile& profile) {
    static bbr::DefaultClock defaultClock;
    conn.SetCongestionControl(bbr::NewBbrSender(
        defaultClock,
        SeedPacketSize(1350 /* initial packet size */,
                       bbr::GetInitialPacketSize(conn.RemoteAddr())),
        profile));
}

// UseBrutal attaches a Brutal controller to the connection.
inline void UseBrutal(IQuicConnection& conn, uint64_t tx, bool disableLossCompensation) {
    conn.SetCongestionControl(std::make_shared<BrutalSender>(tx, disableLossCompensation));
}

// UseConfigured attaches the configured (default) controller.
inline void UseConfigured(IQuicConnection& conn, const std::string& congestionType,
                          const std::string& bbrProfile) {
    if (congestionType == TypeReno) {
        // Reno: leave the QUIC stack's built-in default in place.
        return;
    }
    UseBBR(conn, bbr::Profile(bbrProfile));
}

} // namespace hy2::cc
