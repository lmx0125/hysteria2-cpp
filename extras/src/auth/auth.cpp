// auth.cpp - rewrite of extras/auth (password.go, userpass.go, http.go,
// command.go).
#include "hy2/auth/auth.hpp"

#include <cstdio>
#include <string>
#include <vector>

#include "hy2/error.hpp"

namespace hy2::auth {

namespace {

std::string asciiToLower(const std::string& s) {
    std::string r = s;
    for (char& c : r) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return r;
}

// strings.TrimSpace (ASCII whitespace).
std::string trimSpace(const std::string& s) {
    static const char* ws = " \t\n\v\f\r";
    size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

// ---------------------------------------------------------------------------
// Minimal JSON support mirroring encoding/json's behavior for our payloads.

// json.Marshal string escaping with default HTML escaping enabled.
void jsonAppendString(std::string& out, const std::string& s) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '<': out += "\\u003c"; break;
        case '>': out += "\\u003e"; break;
        case '&': out += "\\u0026"; break;
        default:
            if (c < 0x20) {
                static const char hex[] = "0123456789abcdef";
                out += "\\u00";
                out += hex[(c >> 4) & 0xf];
                out += hex[c & 0xf];
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    // U+2028 / U+2029 escaping
    // (handled in a post pass to keep the switch simple)
    const std::string ls = "\xE2\x80\xA8";
    const std::string ps = "\xE2\x80\xA9";
    for (const std::string* esc : {&ls, &ps}) {
        std::string repl = (*esc == ls) ? "\\u2028" : "\\u2029";
        size_t pos = 0;
        while ((pos = out.find(*esc, pos)) != std::string::npos) {
            out.replace(pos, esc->size(), repl);
            pos += repl.size();
        }
    }
    out += '"';
}

struct JsonParser {
    const std::string& s;
    size_t i = 0;

    explicit JsonParser(const std::string& body) : s(body) {}

    void skipWs() {
        while (i < s.size()) {
            char c = s[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++;
            else break;
        }
    }

    bool peek(char c) const { return i < s.size() && s[i] == c; }

    [[noreturn]] void fail() { throw Error("invalid JSON response"); }

    void expect(char c) {
        skipWs();
        if (!peek(c)) fail();
        i++;
    }

    bool parseHex4(unsigned& out) {
        if (i + 4 > s.size()) return false;
        unsigned v = 0;
        for (int k = 0; k < 4; k++) {
            char c = s[i + k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned>(c - 'a') + 10;
            else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned>(c - 'A') + 10;
            else return false;
        }
        i += 4;
        out = v;
        return true;
    }

    void appendUtf8(std::string& out, unsigned cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    void parseString(std::string& out) {
        expect('"');
        out.clear();
        while (true) {
            if (i >= s.size()) fail();
            char c = s[i++];
            if (c == '"') break;
            if (static_cast<unsigned char>(c) < 0x20) fail(); // raw control char
            if (c == '\\') {
                if (i >= s.size()) fail();
                char e = s[i++];
                switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    unsigned cp;
                    if (!parseHex4(cp)) fail();
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < s.size() &&
                        s[i] == '\\' && s[i + 1] == 'u') {
                        size_t save = i;
                        i += 2;
                        unsigned lo;
                        if (parseHex4(lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else {
                            i = save; // lone surrogate => U+FFFD (Go behavior)
                            cp = 0xFFFD;
                        }
                    } else if (cp >= 0xD800 && cp <= 0xDFFF) {
                        cp = 0xFFFD; // lone surrogate (Go behavior)
                    }
                    appendUtf8(out, cp);
                    break;
                }
                default: fail();
                }
            } else {
                out += c;
            }
        }
    }

    bool parseBool() {
        skipWs();
        if (s.compare(i, 4, "true") == 0) {
            i += 4;
            return true;
        }
        if (s.compare(i, 5, "false") == 0) {
            i += 5;
            return false;
        }
        fail();
    }

    void skipValue(int depth) {
        skipWs();
        if (depth > 64) fail();
        if (i >= s.size()) fail();
        char c = s[i];
        if (c == '"' || c == '[' || c == '{') {
            std::string tmp;
            if (c == '"') {
                parseString(tmp);
                return;
            }
            char close = (c == '[') ? ']' : '}';
            i++;
            skipWs();
            if (peek(close)) {
                i++;
                return;
            }
            while (true) {
                skipValue(depth + 1); // object keys are strings; arrays are values
                skipWs();
                if (peek(':')) {
                    i++;
                    continue;
                }
                if (peek(',')) {
                    i++;
                    continue;
                }
                expect(close);
                return;
            }
        }
        // number / true / false / null
        size_t start = i;
        while (i < s.size()) {
            char d = s[i];
            if ((d >= '0' && d <= '9') || (d >= 'a' && d <= 'z') ||
                (d >= 'A' && d <= 'Z') || d == '-' || d == '+' || d == '.') {
                i++;
            } else {
                break;
            }
        }
        if (i == start) fail();
    }
};

// Parses {"ok":bool,"id":"..."} (extra keys ignored, key order free).
void parseAuthResponse(const std::string& body, bool& okOut, std::string& idOut) {
    JsonParser p(body);
    okOut = false;
    idOut.clear();
    p.expect('{');
    p.skipWs();
    if (p.peek('}')) {
        p.expect('}');
        return;
    }
    while (true) {
        std::string key;
        p.parseString(key);
        p.expect(':');
        p.skipWs();
        if (key == "ok") {
            okOut = p.parseBool();
        } else if (key == "id") {
            p.parseString(idOut);
        } else {
            p.skipValue(0);
        }
        p.skipWs();
        if (p.peek(',')) {
            p.i++;
            continue;
        }
        p.expect('}');
        break;
    }
}

// Windows command-line argument quoting (MSVCRT CommandLineToArgvW rules).
std::string quoteArg(const std::string& arg) {
    bool needQuote = arg.empty();
    for (char c : arg) {
        if (c == ' ' || c == '\t' || c == '"') {
            needQuote = true;
            break;
        }
    }
    if (!needQuote) return arg;
    std::string r = "\"";
    size_t backslashes = 0;
    for (char c : arg) {
        if (c == '\\') {
            backslashes++;
            continue;
        }
        if (c == '"') {
            r.append(backslashes * 2 + 1, '\\');
            r += '"';
        } else {
            r.append(backslashes, '\\');
            r += c;
        }
        backslashes = 0;
    }
    r.append(backslashes * 2, '\\');
    r += '"';
    return r;
}

} // namespace

// ---------------------------------------------------------------------------
// PasswordAuthenticator

bool PasswordAuthenticator::Authenticate(const std::string& /* addr */,
                                         const std::string& auth, uint64_t /* tx */,
                                         std::string& idOut) {
    if (auth == Password) {
        idOut = "user";
        return true;
    }
    idOut.clear();
    return false;
}

// ---------------------------------------------------------------------------
// UserPassAuthenticator

UserPassAuthenticator::UserPassAuthenticator(std::map<std::string, std::string> users) {
    // Usernames are case-insensitive.
    for (auto& kv : users) {
        users_[asciiToLower(kv.first)] = std::move(kv.second);
    }
}

bool UserPassAuthenticator::Authenticate(const std::string& /* addr */,
                                         const std::string& auth, uint64_t /* tx */,
                                         std::string& idOut) {
    size_t sep = auth.find(':');
    if (sep == std::string::npos) {
        idOut.clear();
        return false;
    }
    std::string user = asciiToLower(auth.substr(0, sep));
    std::string pass = auth.substr(sep + 1);
    auto it = users_.find(user);
    if (it == users_.end() || it->second != pass) {
        idOut.clear();
        return false;
    }
    idOut = user;
    return true;
}

// ---------------------------------------------------------------------------
// HttpAuthenticator

HttpAuthenticator::HttpAuthenticator(std::string url, HttpClientFunc client)
    : url_(std::move(url)), client_(std::move(client)) {}

HttpAuthenticator::AuthResponse HttpAuthenticator::post(const std::string& addr,
                                                        const std::string& auth,
                                                        uint64_t tx) {
    // Mirrors Go: json.Marshal(httpAuthRequest{Addr, Auth, Tx})
    std::string body = "{\"addr\":";
    jsonAppendString(body, addr);
    body += ",\"auth\":";
    jsonAppendString(body, auth);
    body += ",\"tx\":";
    body += std::to_string(tx);
    body += "}";

    HttpClientRequest hreq;
    hreq.URL = url_;
    hreq.ContentType = "application/json";
    hreq.Body = std::move(body);

    HttpClientResponse hresp = client_(hreq); // may throw => transport error
    if (hresp.StatusCode != 200) {
        throw Error("invalid status code");
    }
    AuthResponse resp;
    parseAuthResponse(hresp.Body, resp.OK, resp.ID);
    return resp;
}

bool HttpAuthenticator::Authenticate(const std::string& addr, const std::string& auth,
                                     uint64_t tx, std::string& idOut) {
    try {
        AuthResponse resp = post(addr, auth, tx);
        idOut = resp.ID;
        return resp.OK;
    } catch (...) {
        idOut.clear();
        return false;
    }
}

// ---------------------------------------------------------------------------
// CommandAuthenticator

bool CommandAuthenticator::Authenticate(const std::string& addr, const std::string& auth,
                                        uint64_t tx, std::string& idOut) {
    // Go: exec.Command(Cmd, addr.String(), auth, strconv.Itoa(int(tx)))
    std::string cmdline = Cmd;
    cmdline += " ";
    cmdline += quoteArg(addr);
    cmdline += " ";
    cmdline += quoteArg(auth);
    cmdline += " ";
    cmdline += quoteArg(std::to_string(tx));

#ifdef _WIN32
    FILE* pipe = _popen(cmdline.c_str(), "r");
#else
    // POSIX: popen/pclose (no leading underscore). The command is run via
    // /bin/sh, mirroring cmd.exe on Windows.
    FILE* pipe = popen(cmdline.c_str(), "r");
#endif
    if (pipe == nullptr) {
        // Includes failing to execute the command.
        idOut.clear();
        return false;
    }
    std::string out;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), pipe)) > 0) {
        out.append(buf, n);
    }
#ifdef _WIN32
    int rc = _pclose(pipe);
#else
    int rc = pclose(pipe);
#endif
    if (rc != 0) {
        // Or the command exiting with a non-zero exit code.
        idOut.clear();
        return false;
    }
    idOut = trimSpace(out);
    return true;
}

} // namespace hy2::auth
