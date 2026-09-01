// auth.hpp - Rewrite of extras/auth (password.go, userpass.go, http.go,
// command.go). All authenticators implement hy2::server::Authenticator.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>

#include "hy2/server_iface.hpp"

namespace hy2::auth {

// ---------------------------------------------------------------------------
// HTTP client injection. Go uses net/http directly; the C++ core ships no
// HTTP stack, so callers supply the transport. Mirrors (*http.Client).Post:
// transport failures are signaled by throwing (Go err != nil).
struct HttpClientRequest {
    std::string URL;
    std::string ContentType;
    std::string Body;
};

struct HttpClientResponse {
    int StatusCode = 0;
    std::string Body;
};

using HttpClientFunc = std::function<HttpClientResponse(const HttpClientRequest&)>;

// ---------------------------------------------------------------------------
// PasswordAuthenticator checks the password against a single string.
// Go: id is "user" on success.
class PasswordAuthenticator : public server::Authenticator {
public:
    std::string Password;

    explicit PasswordAuthenticator(std::string password) : Password(std::move(password)) {}

    bool Authenticate(const std::string& addr, const std::string& auth, uint64_t tx,
                      std::string& idOut) override;
};

// UserPassAuthenticator checks "username:password" against a map of
// username/password pairs. Usernames are case-insensitive. The user map is
// immutable after construction, hence thread-safe (mirrors Go).
class UserPassAuthenticator : public server::Authenticator {
public:
    explicit UserPassAuthenticator(std::map<std::string, std::string> users);

    bool Authenticate(const std::string& addr, const std::string& auth, uint64_t tx,
                      std::string& idOut) override;

private:
    std::map<std::string, std::string> users_;
};

// HttpAuthenticator POSTs {"addr":..,"auth":..,"tx":..} as JSON to the
// configured URL and expects {"ok":bool,"id":"..."} back with status 200
// (status != 200 => error "invalid status code"). Any client/parse failure
// results in (false, "").
class HttpAuthenticator : public server::Authenticator {
public:
    // Note: Go's insecure TLS flag is a transport concern and lives in the
    // injected client.
    HttpAuthenticator(std::string url, HttpClientFunc client);

    bool Authenticate(const std::string& addr, const std::string& auth, uint64_t tx,
                      std::string& idOut) override;

private:
    struct AuthResponse {
        bool OK = false;
        std::string ID;
    };
    AuthResponse post(const std::string& addr, const std::string& auth, uint64_t tx);

    std::string url_;
    HttpClientFunc client_;
};

// CommandAuthenticator runs Cmd with <addr> <auth> <tx> appended as
// arguments and reads stdout; exit code 0 == success with id being the
// whitespace-trimmed output. On Windows the command line is executed via
// _popen/_pclose (cmd.exe), so Cmd may contain shell syntax.
class CommandAuthenticator : public server::Authenticator {
public:
    std::string Cmd;

    explicit CommandAuthenticator(std::string cmd) : Cmd(std::move(cmd)) {}

    bool Authenticate(const std::string& addr, const std::string& auth, uint64_t tx,
                      std::string& idOut) override;
};

} // namespace hy2::auth
