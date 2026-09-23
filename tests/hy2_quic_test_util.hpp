// hy2_quic_test_util.hpp - Shared helpers for tests that spin up a real
// ngtcp2 QUIC client/server pair over UDP loopback.
#pragma once

#ifdef HY2_WITH_QUIC_BACKEND

#include <string>

#include "hy2/server_iface.hpp"

namespace hy2test {

// Self-signed EC cert/key for 127.0.0.1 (same pair as the local test bed).
inline const char kTestCertPem[] = R"PEM(-----BEGIN CERTIFICATE-----
MIIBeTCCAR6gAwIBAgIUCvDGrKrVOErQk61KeYgVKcW4nSMwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkxNDEzNTAzM1oXDTI3MDkxNDEz
NTAzM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEI80licD9NPa+uK6xaOS0JMJWnb3DkydnQNe3q8TrMsapNU/l50C9taLS
pP+O+5MThCeU8lviartSh9KmKX56U6NOMEwwHQYDVR0OBBYEFBHZT0wGvHe2BvmU
Wv4x9uHEqnO7MA8GA1UdEwEB/wQFMAMBAf8wGgYDVR0RBBMwEYIJbG9jYWxob3N0
hwR/AAABMAoGCCqGSM49BAMCA0kAMEYCIQDy99tMMAVhiBuWYLEt22H6oPynsBRi
uLV+Y/QtnIaP3AIhAO65jMYRY57HD5ozMX7WcR4glC7vpBvQxkIuRqrZiqUC
-----END CERTIFICATE-----
)PEM";

inline const char kTestKeyPem[] = R"PEM(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTt/ulMiE7nSDCdsP
roxnN2YbdgokcKuD2XkJIWWnJ9WhRANCAAQjzSWJwP009r64rrFo5LQkwladvcOT
J2dA17erxOsyxqk1T+XnQL21otKk/477kxOEJ5TyW+Jqu1KH0qYpfnpT
-----END PRIVATE KEY-----
)PEM";

// Accepts the shared test password for any request.
class TestAuth : public hy2::server::Authenticator {
public:
    static constexpr const char* kPassword = "test123";

    bool Authenticate(const std::string&, const std::string& auth,
                      uint64_t, std::string& idOut) override {
        if (auth != kPassword) return false;
        idOut = "quic-test";
        return true;
    }
};

} // namespace hy2test

#endif // HY2_WITH_QUIC_BACKEND
