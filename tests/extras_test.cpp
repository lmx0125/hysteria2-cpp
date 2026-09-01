// extras_test.cpp - tests for the hy2::extras packages (auth, masq, sniff,
// udphop, speedtest).
#include "hytest.hpp"

#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "hy2/auth/auth.hpp"
#include "hy2/error.hpp"
#include "hy2/io.hpp"
#include "hy2/masq/masq.hpp"
#include "hy2/server_iface.hpp"
#include "hy2/sniff/sniff.hpp"
#include "hy2/speedtest/speedtest.hpp"
#include "hy2/udphop/udphop.hpp"

using namespace hy2;

// ---------------------------------------------------------------------------
// Local test doubles

namespace {

class FakeStream : public IHyStream {
public:
    FakeStream(const uint8_t* d, size_t n) : copy_(d, d + n), pos_(0) {}
    explicit FakeStream(const std::string& s) : copy_(s.begin(), s.end()), pos_(0) {}

    size_t Read(uint8_t* p, size_t n) override {
        if (pos_ >= copy_.size()) return 0;
        size_t got = n < copy_.size() - pos_ ? n : copy_.size() - pos_;
        std::memcpy(p, copy_.data() + pos_, got);
        pos_ += got;
        return got;
    }
    void Write(const uint8_t*, size_t) override { throw Error("write not supported"); }
    uint64_t StreamID() const override { return 0; }
    void Close() override {}
    void CancelRead(StreamErrorCode) override {}
    void CancelWrite(StreamErrorCode) override {}
    void SetReadDeadline(MonoTime t) override {
        lastDeadline_ = t;
        deadlineCalls_++;
    }

    MonoTime lastDeadline_{};
    int deadlineCalls_ = 0;

private:
    std::vector<uint8_t> copy_;
    size_t pos_ = 0;
};

class CaptureWriter : public server::HttpResponseWriter {
public:
    server::HeaderMap Hdr;
    int Status = -1;
    bool HeaderWritten = false;
    std::vector<uint8_t> Body;

    server::HeaderMap& Header() override { return Hdr; }
    void WriteHeader(int status) override {
        Status = status;
        HeaderWritten = true;
    }
    void Write(const uint8_t* p, size_t n) override { Body.insert(Body.end(), p, p + n); }

    std::string BodyStr() const {
        return std::string(reinterpret_cast<const char*>(Body.data()), Body.size());
    }
};

class VectorWriter : public IByteWriter {
public:
    std::vector<uint8_t> Buf;
    void Write(const uint8_t* p, size_t n) override { Buf.insert(Buf.end(), p, p + n); }
};

struct FakeApp : public server::IHttpHandler {
    void ServeHTTP(server::HttpResponseWriter& w, const server::HttpRequest&) override {
        w.Header()["Alt-Svc"] = "h3=\":999\"; ma=60";
        w.Header()["X-App"] = "yes";
        w.WriteHeader(200);
        const uint8_t body[] = "hello masq";
        w.Write(body, sizeof(body) - 1);
    }
};

bool bytesEqual(const std::vector<uint8_t>& a, const std::string& b) {
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), b.size()) == 0;
}

void checkBytesEq(const std::vector<uint8_t>& got, const std::vector<uint8_t>& want,
                  int line) {
    if (got != want) {
        std::ostringstream os;
        os << "byte mismatch at line " << line << ": got " << got.size()
           << " bytes, want " << want.size();
        throw std::runtime_error(os.str());
    }
}

} // namespace

// ---------------------------------------------------------------------------
// auth

HY_TEST(auth_password) {
    auth::PasswordAuthenticator a("hello");
    std::string id;
    HY_CHECK(a.Authenticate("1.2.3.4:5678", "hello", 42, id));
    HY_CHECK_EQ(id, std::string("user"));
    HY_CHECK(!a.Authenticate("1.2.3.4:5678", "world", 42, id));
    HY_CHECK_EQ(id, std::string(""));
    // Empty password must still match exactly
    auth::PasswordAuthenticator b("");
    HY_CHECK(b.Authenticate("", "", 0, id));
    HY_CHECK_EQ(id, std::string("user"));
    HY_CHECK(!b.Authenticate("", "x", 0, id));
    HY_CHECK_EQ(id, std::string(""));
}

HY_TEST(auth_userpass) {
    auth::UserPassAuthenticator a(std::map<std::string, std::string>{
        {"wang", "123"},
        {"saul", "goodman"},
    });
    std::string id;
    HY_CHECK(a.Authenticate("", "wang:123", 0, id));
    HY_CHECK_EQ(id, std::string("wang"));
    HY_CHECK(!a.Authenticate("", "random:stranger", 0, id));
    HY_CHECK_EQ(id, std::string(""));
    HY_CHECK(!a.Authenticate("", "poop", 0, id)); // no separator
    HY_CHECK_EQ(id, std::string(""));
    // Wrong password
    HY_CHECK(!a.Authenticate("", "wang:456", 0, id));
    HY_CHECK_EQ(id, std::string(""));
    // Case-insensitive username
    auth::UserPassAuthenticator b(std::map<std::string, std::string>{
        {"gawR", "gura"},
        {"fubuki", "shirakami"},
    });
    HY_CHECK(b.Authenticate("", "Gawr:gura", 0, id));
    HY_CHECK_EQ(id, std::string("gawr"));
    // Password case matters
    HY_CHECK(!b.Authenticate("", "gawr:GURA", 0, id));
    HY_CHECK_EQ(id, std::string(""));
}

HY_TEST(auth_http) {
    auth::HttpClientRequest captured;
    bool shouldThrow = false;
    int statusToReturn = 200;
    std::string bodyToReturn = "{\"ok\":true,\"id\":\"some_unique_id\"}";
    auth::HttpAuthenticator a(
        "http://127.0.0.1:5000/auth",
        [&](const auth::HttpClientRequest& req) -> auth::HttpClientResponse {
            if (shouldThrow) throw Error("dial tcp: connection refused");
            captured = req;
            return auth::HttpClientResponse{statusToReturn, bodyToReturn};
        });

    std::string id;
    HY_CHECK(a.Authenticate("123.123.123.123:5566", "wahaha", 12345, id));
    HY_CHECK_EQ(id, std::string("some_unique_id"));
    HY_CHECK_EQ(captured.URL, std::string("http://127.0.0.1:5000/auth"));
    HY_CHECK_EQ(captured.ContentType, std::string("application/json"));
    HY_CHECK_EQ(captured.Body,
                std::string("{\"addr\":\"123.123.123.123:5566\",\"auth\":\"wahaha\","
                            "\"tx\":12345}"));

    // Non-OK response => not authenticated (invalid status code path)
    statusToReturn = 403;
    HY_CHECK(!a.Authenticate("1.2.3.4:5678", "idk", 123, id));
    HY_CHECK_EQ(id, std::string(""));

    // Transport error => not authenticated
    statusToReturn = 200;
    shouldThrow = true;
    HY_CHECK(!a.Authenticate("1.2.3.4:5678", "idk", 123, id));
    HY_CHECK_EQ(id, std::string(""));
    shouldThrow = false;

    // JSON key order free, extra keys ignored
    bodyToReturn = R"({"id":"the_id","ok":true,"extra":[1,2,{"z":3}],"n":null})";
    HY_CHECK(a.Authenticate("1.2.3.4:1", "pw", 7, id));
    HY_CHECK_EQ(id, std::string("the_id"));

    // ok:false (Go still returns the id from the response)
    bodyToReturn = "{\"ok\":false,\"id\":\"nope\"}";
    HY_CHECK(!a.Authenticate("1.2.3.4:1", "pw", 7, id));
    HY_CHECK_EQ(id, std::string("nope"));

    // Malformed JSON body => not authenticated
    bodyToReturn = "{not json";
    HY_CHECK(!a.Authenticate("1.2.3.4:1", "pw", 7, id));
    HY_CHECK_EQ(id, std::string(""));

    // JSON escaping of the request body (encoding/json HTML escaping)
    bodyToReturn = "{\"ok\":true,\"id\":\"x\"}";
    (void)a.Authenticate("1.2.3.4:1", "a\"b&c<d", 7, id);
    HY_CHECK_EQ(captured.Body,
                std::string("{\"addr\":\"1.2.3.4:1\",\"auth\":"
                            "\"a\\\"b\\u0026c\\u003cd\",\"tx\":7}"));
}

HY_TEST(auth_command) {
#ifdef _WIN32
    auth::CommandAuthenticator echo("cmd /c echo");
#else
    // popen runs via /bin/sh -c on POSIX
    auth::CommandAuthenticator echo("echo");
#endif
    std::string id;
    // Shell-safe arguments are echoed back verbatim.
    HY_CHECK(echo.Authenticate("1.2.3.4:5678", "pw123", 7, id));
    HY_CHECK_EQ(id, std::string("1.2.3.4:5678 pw123 7"));

#ifdef _WIN32
    // Arguments with spaces are quoted per MSVCRT rules; cmd's echo keeps
    // the quotes in the output.
    HY_CHECK(echo.Authenticate("1.2.3.4:5678", "hello world", 7, id));
    HY_CHECK_EQ(id, std::string("1.2.3.4:5678 \"hello world\" 7"));
#else
    // sh consumes the quotes when passing the argument to echo.
    HY_CHECK(echo.Authenticate("1.2.3.4:5678", "hello world", 7, id));
    HY_CHECK_EQ(id, std::string("1.2.3.4:5678 hello world 7"));
#endif

#ifdef _WIN32
    auth::CommandAuthenticator fail("cmd /c exit 3");
#else
    // Non-zero exit code => failure (pclose reports non-zero wait status)
    auth::CommandAuthenticator fail("exit 3");
#endif
    HY_CHECK(!fail.Authenticate("1.2.3.4:5678", "pw", 7, id));
    HY_CHECK_EQ(id, std::string(""));

#ifdef _WIN32
    auth::CommandAuthenticator okNoOut("cmd /c exit 0");
#else
    // Exit code zero without output => success with empty id
    auth::CommandAuthenticator okNoOut("exit 0");
#endif
    HY_CHECK(okNoOut.Authenticate("1.2.3.4:5678", "pw", 7, id));
    HY_CHECK_EQ(id, std::string(""));
}

// ---------------------------------------------------------------------------
// masq

HY_TEST(masq_redirect) {
    masq::MasqTCPServer m;
    m.ForceHTTPS = true;
    m.HTTPSPort = 443;
    m.QUICPort = 443;

    server::HttpRequest req;
    req.Method = "GET";
    req.Host = "example.com";
    req.Path = "/foo?a=b";

    CaptureWriter w;
    m.ServeHTTP(w, req);
    HY_CHECK_EQ(w.Status, 301);
    HY_CHECK(w.HeaderWritten);
    HY_CHECK_EQ(w.Hdr["Location"], std::string("https://example.com/foo?a=b"));
    HY_CHECK_EQ(w.Hdr["Content-Type"], std::string("text/html; charset=utf-8"));
    HY_CHECK_EQ(w.BodyStr(),
                std::string("<a href=\"https://example.com/foo?a=b\">Moved "
                            "Permanently</a>.\n\n"));

    // Custom HTTPS port is included in the redirect
    m.HTTPSPort = 8443;
    CaptureWriter w2;
    m.ServeHTTP(w2, req);
    HY_CHECK_EQ(w2.Hdr["Location"], std::string("https://example.com:8443/foo?a=b"));
    HY_CHECK_EQ(w2.BodyStr(),
                std::string("<a href=\"https://example.com:8443/foo?a=b\">Moved "
                            "Permanently</a>.\n\n"));

    // POST gets a Location but no Content-Type/body
    m.HTTPSPort = 443;
    req.Method = "POST";
    CaptureWriter w3;
    m.ServeHTTP(w3, req);
    HY_CHECK_EQ(w3.Status, 301);
    HY_CHECK_EQ(w3.Hdr["Location"], std::string("https://example.com/foo?a=b"));
    HY_CHECK(w3.Hdr.find("Content-Type") == w3.Hdr.end());
    HY_CHECK(w3.Body.empty());
}

HY_TEST(masq_altsvc) {
    masq::MasqTCPServer m;
    m.QUICPort = 443;
    m.Handler = std::make_shared<FakeApp>();

    server::HttpRequest req;
    req.Method = "GET";
    req.Host = "example.com";
    req.Path = "/";

    CaptureWriter w;
    m.ServeHTTP(w, req);
    HY_CHECK_EQ(w.Status, 200);
    // The handler's own Alt-Svc must be overridden by our port
    HY_CHECK_EQ(w.Hdr["Alt-Svc"], std::string("h3=\":443\"; ma=2592000"));
    HY_CHECK_EQ(w.Hdr["X-App"], std::string("yes"));
    HY_CHECK_EQ(w.BodyStr(), std::string("hello masq"));

    // Custom QUIC port shows up in Alt-Svc
    m.QUICPort = 8443;
    CaptureWriter w2;
    m.ServeHTTP(w2, req);
    HY_CHECK_EQ(w2.Hdr["Alt-Svc"], std::string("h3=\":8443\"; ma=2592000"));
}

// ---------------------------------------------------------------------------
// sniff

HY_TEST(sniff_check) {
    sniff::Sniffer sniffer;
    sniffer.Timeout = Duration::FromSeconds(1);

    HY_CHECK(sniffer.Check(false, "1.1.1.1:80"));
    HY_CHECK(!sniffer.Check(false, "example.com:443"));

    sniffer.RewriteDomain = true;
    HY_CHECK(sniffer.Check(false, "example.com:443"));

    sniffer.TCPPorts = PortUnion{PortRange{80, 80}};
    HY_CHECK(sniffer.Check(false, "google.com:80"));
    HY_CHECK(!sniffer.Check(false, "google.com:443"));

    sniffer.UDPPorts = PortUnion{PortRange{443, 443}};
    HY_CHECK(sniffer.Check(true, "google.com:443"));
    HY_CHECK(!sniffer.Check(true, "google.com:80"));

    // Internal addresses (@ prefix) are never sniffed
    HY_CHECK(!sniffer.Check(true, "@speedtest"));
    // Malformed addresses are never sniffed
    HY_CHECK(!sniffer.Check(false, "nonsense"));
    // Empty port unions mean "all ports"
    sniff::Sniffer allPorts;
    allPorts.RewriteDomain = true;
    HY_CHECK(allPorts.Check(false, "any.org:65001"));
}

HY_TEST(sniff_http) {
    sniff::Sniffer sniffer;
    sniffer.Timeout = Duration::FromSeconds(1);

    const std::string httpReq =
        "POST /hello HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: mamamiya\r\n"
        "Content-Length: 27\r\n"
        "Connection: keep-alive\r\n\r\n"
        "param1=value1&param2=value2";

    // Rewrite IP to domain
    {
        FakeStream stream(httpReq);
        std::string reqAddr = "111.111.111.111:80";
        auto putback = sniffer.TCP(stream, reqAddr);
        HY_CHECK(bytesEqual(putback, httpReq));
        HY_CHECK_EQ(reqAddr, std::string("example.com:80"));
        HY_CHECK(stream.deadlineCalls_ >= 2); // set + reset
        HY_CHECK(stream.lastDeadline_.IsZero());
    }

    // Host header as host:port keeps only the host part
    {
        const std::string req2 = "GET / HTTP/1.1\r\n"
                                 "Host: example.com:8080\r\n"
                                 "User-Agent: test-agent\r\n"
                                 "Accept: */*\r\n\r\n";
        FakeStream stream(req2);
        std::string reqAddr = "222.222.222.222:10086";
        auto putback = sniffer.TCP(stream, reqAddr);
        HY_CHECK(bytesEqual(putback, req2));
        HY_CHECK_EQ(reqAddr, std::string("example.com:10086"));
    }

    // Unrecognized protocol that looks like letters: parsed as HTTP, fails,
    // everything is put back untouched
    {
        const std::string req3 = "Wait It's All Ohio? Always Has Been.";
        FakeStream stream(req3);
        std::string reqAddr = "123.123.123.123:123";
        auto putback = sniffer.TCP(stream, reqAddr);
        HY_CHECK(bytesEqual(putback, req3));
        HY_CHECK_EQ(reqAddr, std::string("123.123.123.123:123"));
    }

    // Unrecognized binary: only the initial 3 bytes are put back
    {
        FakeStream stream(std::string("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a", 10));
        std::string reqAddr = "45.45.45.45:45";
        auto putback = sniffer.TCP(stream, reqAddr);
        HY_CHECK(bytesEqual(putback, "\x01\x02\x03"));
        HY_CHECK_EQ(reqAddr, std::string("45.45.45.45:45"));
    }

    // Not enough data: partial buffer returned, no rewrite
    {
        FakeStream stream(std::string("AB"));
        std::string reqAddr = "66.66.66.66:66";
        auto putback = sniffer.TCP(stream, reqAddr);
        HY_CHECK(bytesEqual(putback, "AB"));
        HY_CHECK_EQ(reqAddr, std::string("66.66.66.66:66"));
    }

    // Invalid reqAddr (no port) makes the rewrite fail hard
    {
        FakeStream stream(httpReq);
        std::string reqAddr = "just-a-host";
        bool threw = false;
        try {
            (void)sniffer.TCP(stream, reqAddr);
        } catch (const Error&) {
            threw = true;
        }
        HY_CHECK(threw);
    }
}

namespace {
// Builds a minimal TLS record containing one ClientHello handshake message
// with an SNI extension (+ one extra extension to exercise the walker).
std::vector<uint8_t> buildClientHelloRecord(const std::string& sni) {
    std::vector<uint8_t> list;
    list.push_back(0x00); // name_type: host_name
    list.push_back(static_cast<uint8_t>((sni.size() >> 8) & 0xff));
    list.push_back(static_cast<uint8_t>(sni.size() & 0xff));
    list.insert(list.end(), sni.begin(), sni.end());

    std::vector<uint8_t> sniPayload;
    uint16_t listLen = static_cast<uint16_t>(list.size());
    sniPayload.push_back(static_cast<uint8_t>((listLen >> 8) & 0xff));
    sniPayload.push_back(static_cast<uint8_t>(listLen & 0xff));
    sniPayload.insert(sniPayload.end(), list.begin(), list.end());

    std::vector<uint8_t> extData;
    auto appendExt = [&](uint16_t type, const std::vector<uint8_t>& payload) {
        extData.push_back(static_cast<uint8_t>((type >> 8) & 0xff));
        extData.push_back(static_cast<uint8_t>(type & 0xff));
        extData.push_back(static_cast<uint8_t>((payload.size() >> 8) & 0xff));
        extData.push_back(static_cast<uint8_t>(payload.size() & 0xff));
        extData.insert(extData.end(), payload.begin(), payload.end());
    };
    appendExt(0x0000, sniPayload);      // server_name
    appendExt(0x000b, {0x01, 0x00});    // ec_point_formats

    std::vector<uint8_t> body;
    body.push_back(0x03);
    body.push_back(0x03); // client version TLS 1.2
    for (int i = 0; i < 32; i++) body.push_back(static_cast<uint8_t>(i)); // random
    body.push_back(0x00);                                    // session id len
    body.push_back(0x00);
    body.push_back(0x02); // cipher suites len
    body.push_back(0x13);
    body.push_back(0x01);
    body.push_back(0x01); // compression methods len
    body.push_back(0x00);
    size_t extLen = extData.size();
    body.push_back(static_cast<uint8_t>((extLen >> 8) & 0xff));
    body.push_back(static_cast<uint8_t>(extLen & 0xff));
    body.insert(body.end(), extData.begin(), extData.end());

    std::vector<uint8_t> hs;
    hs.push_back(0x01); // handshake type: client_hello
    hs.push_back(static_cast<uint8_t>((body.size() >> 16) & 0xff));
    hs.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xff));
    hs.push_back(static_cast<uint8_t>(body.size() & 0xff));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<uint8_t> record;
    record.push_back(0x16); // handshake
    record.push_back(0x03);
    record.push_back(0x01); // TLS 1.0 record version
    record.push_back(static_cast<uint8_t>((hs.size() >> 8) & 0xff));
    record.push_back(static_cast<uint8_t>(hs.size() & 0xff));
    record.insert(record.end(), hs.begin(), hs.end());
    return record;
}
} // namespace

HY_TEST(sniff_tls_sni) {
    sniff::Sniffer sniffer;
    sniffer.Timeout = Duration::FromSeconds(1);

    // Basic SNI extraction rewrites the address
    {
        auto rec = buildClientHelloRecord("www.example.com");
        FakeStream stream(std::string(rec.begin(), rec.end()));
        std::string reqAddr = "222.222.222.222:443";
        auto putback = sniffer.TCP(stream, reqAddr);
        HY_CHECK(std::memcmp(putback.data(), rec.data(), rec.size()) == 0 &&
                 putback.size() == rec.size());
        HY_CHECK_EQ(reqAddr, std::string("www.example.com:443"));
    }

    // Trailing dot in SNI is trimmed (crypto/tls behavior)
    {
        auto rec = buildClientHelloRecord("ipinfo.io.");
        FakeStream stream(std::string(rec.begin(), rec.end()));
        std::string reqAddr = "222.222.222.222:443";
        (void)sniffer.TCP(stream, reqAddr);
        HY_CHECK_EQ(reqAddr, std::string("ipinfo.io:443"));
    }

    // Truncated record: whatever arrived is put back, no rewrite
    {
        auto full = buildClientHelloRecord("www.example.com");
        std::string partial(reinterpret_cast<const char*>(full.data()), 12);
        FakeStream stream(partial);
        std::string reqAddr = "10.0.0.1:443";
        auto putback = sniffer.TCP(stream, reqAddr);
        HY_CHECK(putback.size() == 12 || putback.size() == 15);
        HY_CHECK_EQ(reqAddr, std::string("10.0.0.1:443"));
    }

    // Direct parser checks
    {
        auto rec = buildClientHelloRecord("a.b.c");
        auto sni = sniff::UnmarshalClientHelloSNI(rec.data() + 5, rec.size() - 5);
        HY_CHECK(sni.has_value());
        HY_CHECK_EQ(*sni, std::string("a.b.c"));

        HY_CHECK(!sniff::UnmarshalClientHelloSNI(rec.data() + 5, rec.size() - 6)
                      .has_value()); // length mismatch
        HY_CHECK(!sniff::UnmarshalClientHelloSNI(rec.data() + 5, 3).has_value());
        std::vector<uint8_t> bad = {0x02}; // wrong handshake type
        bad.resize(40, 0x00);
        HY_CHECK(!sniff::UnmarshalClientHelloSNI(bad.data(), bad.size()).has_value());
    }
}

// ---------------------------------------------------------------------------
// udphop

HY_TEST(udphop_addr) {
    // Simple two ports
    {
        auto a = udphop::ResolveUDPHopAddr("1.2.3.4:80,90");
        HY_CHECK_EQ(a.Network(), std::string("udphop"));
        HY_CHECK_EQ(a.IP, std::string("1.2.3.4"));
        HY_CHECK_EQ(a.PortStr, std::string("80,90"));
        HY_CHECK_EQ(a.Ports.size(), static_cast<size_t>(2));
        HY_CHECK_EQ(a.Ports[0], static_cast<uint16_t>(80));
        HY_CHECK_EQ(a.Ports[1], static_cast<uint16_t>(90));
        HY_CHECK_EQ(a.String(), std::string("1.2.3.4:80,90"));
        auto addrs = a.Addrs();
        HY_CHECK_EQ(addrs.size(), static_cast<size_t>(2));
        HY_CHECK_EQ(addrs[0], std::string("1.2.3.4:80"));
        HY_CHECK_EQ(addrs[1], std::string("1.2.3.4:90"));
    }

    // Range expands into individual ports
    {
        auto a = udphop::ResolveUDPHopAddr("5.6.7.8:100-102");
        HY_CHECK_EQ(a.Ports.size(), static_cast<size_t>(3));
        HY_CHECK_EQ(a.Ports[0], static_cast<uint16_t>(100));
        HY_CHECK_EQ(a.Ports[1], static_cast<uint16_t>(101));
        HY_CHECK_EQ(a.Ports[2], static_cast<uint16_t>(102));
        HY_CHECK_EQ(a.String(), std::string("5.6.7.8:100-102"));
    }

    // IPv6 literal (brackets stripped, canonical form)
    {
        auto a = udphop::ResolveUDPHopAddr("[::1]:443");
        HY_CHECK_EQ(a.IP, std::string("::1"));
        HY_CHECK_EQ(a.String(), std::string("[::1]:443"));
        HY_CHECK_EQ(a.Ports.size(), static_cast<size_t>(1));

        auto b = udphop::ResolveUDPHopAddr("[2001:DB8::1]:443,8443");
        HY_CHECK_EQ(b.IP, std::string("2001:db8::1"));
        HY_CHECK_EQ(b.String(), std::string("[2001:db8::1]:443,8443"));
        HY_CHECK_EQ(b.Ports.size(), static_cast<size_t>(2));
    }

    // Errors carry Go-matching messages
    {
        bool threw = false;
        try {
            (void)udphop::ResolveUDPHopAddr("1.2.3.4:abc");
        } catch (const Error& e) {
            threw = true;
            HY_CHECK_EQ(std::string(e.what()),
                        std::string("abc is not a valid port number or range"));
        }
        HY_CHECK(threw);
    }
    {
        bool threw = false;
        try {
            (void)udphop::ResolveUDPHopAddr("1.2.3.4");
        } catch (const Error& e) {
            threw = true;
            HY_CHECK_EQ(std::string(e.what()),
                        std::string("address 1.2.3.4: missing port in address"));
        }
        HY_CHECK(threw);
    }
    {
        // Hostnames unsupported (no DNS in the C++ port)
        bool threw = false;
        try {
            (void)udphop::ResolveUDPHopAddr("example.com:443");
        } catch (const Error&) {
            threw = true;
        }
        HY_CHECK(threw);
    }
}

// ---------------------------------------------------------------------------
// speedtest protocol

HY_TEST(speedtest_protocol) {
    using namespace speedtest;

    HY_CHECK_EQ(TypeDownload, static_cast<uint8_t>(0x1));
    HY_CHECK_EQ(TypeUpload, static_cast<uint8_t>(0x2));

    // DownloadRequest wire format
    {
        VectorWriter w;
        WriteDownloadRequest(w, 78909912);
        checkBytesEq(w.Buf, {0x01, 0x04, 0xB4, 0x11, 0xD8}, __LINE__);
        VectorWriter w2;
        WriteDownloadRequest(w2, 0);
        checkBytesEq(w2.Buf, {0x01, 0x00, 0x00, 0x00, 0x00}, __LINE__);
    }

    // DownloadRequest parse (incl. incomplete input)
    {
        std::vector<uint8_t> data = {0x00, 0x01, 0xBD, 0xC2};
        SliceReader r(data);
        HY_CHECK_EQ(ReadDownloadRequest(r), static_cast<uint32_t>(114114));
        std::vector<uint8_t> short3 = {0x00, 0x01, 0x02};
        SliceReader rShort(short3);
        HY_CHECK_THROWS(ReadDownloadRequest(rShort), Error);
    }

    // UploadRequest wire format + roundtrip
    {
        VectorWriter w;
        WriteUploadRequest(w, 114514);
        checkBytesEq(w.Buf, {0x02, 0x00, 0x01, 0xBF, 0x52}, __LINE__);
        SliceReader r(w.Buf.data() + 1, w.Buf.size() - 1); // skip type byte
        HY_CHECK_EQ(ReadUploadRequest(r), static_cast<uint32_t>(114514));
    }

    // DownloadResponse: exact bytes for error-with-message, then roundtrips
    {
        VectorWriter w;
        WriteDownloadResponse(w, false, "oops");
        checkBytesEq(w.Buf, {0x01, 0x00, 0x04, 'o', 'o', 'p', 's'}, __LINE__);

        SliceReader r(w.Buf);
        auto res = ReadDownloadResponse(r);
        HY_CHECK(!res.OK);
        HY_CHECK_EQ(res.Message, std::string("oops"));

        VectorWriter w2;
        WriteDownloadResponse(w2, true, "");
        checkBytesEq(w2.Buf, {0x00, 0x00, 0x00}, __LINE__);
        SliceReader r2(w2.Buf);
        auto res2 = ReadDownloadResponse(r2);
        HY_CHECK(res2.OK);
        HY_CHECK_EQ(res2.Message, std::string(""));
    }

    // UploadResponse roundtrip
    {
        VectorWriter w;
        WriteUploadResponse(w, false, "err msg");
        SliceReader r(w.Buf);
        auto res = ReadUploadResponse(r);
        HY_CHECK(!res.OK);
        HY_CHECK_EQ(res.Message, std::string("err msg"));

        VectorWriter w2;
        WriteUploadResponse(w2, true, "done");
        SliceReader r2(w2.Buf);
        auto res2 = ReadUploadResponse(r2);
        HY_CHECK(res2.OK);
        HY_CHECK_EQ(res2.Message, std::string("done"));
    }

    // UploadSummary wire format + roundtrip
    {
        VectorWriter w;
        WriteUploadSummary(w, Duration::FromMillis(10000), 100);
        checkBytesEq(w.Buf, {0x00, 0x00, 0x27, 0x10, 0x00, 0x00, 0x00, 0x64},
                     __LINE__);
        SliceReader r(w.Buf);
        auto s = ReadUploadSummary(r);
        HY_CHECK_EQ(s.duration.Milliseconds(), static_cast<int64_t>(10000));
        HY_CHECK_EQ(s.ReceivedLength, static_cast<uint32_t>(100));
    }
}
