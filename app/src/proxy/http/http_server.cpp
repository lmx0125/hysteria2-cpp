// http_server.cpp - HTTP CONNECT proxy server using Hysteria2 client as outbound.
// Rewrite of app/internal/http/server.go.
// Cross-platform: no platform-specific code.
#include "hy2/proxy/http/http_server.hpp"

#include <algorithm>
#include <cstring>
#include <sstream>
#include <thread>
#include <vector>

#include "hy2/copy.hpp"
#include "hy2/debug_print.hpp"

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

namespace hy2::proxy::http {

namespace {

// Base64 decode
static const int kBase64DecodeTable[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

std::string base64Decode(const std::string& input) {
    std::string output;
    output.reserve(input.size() * 3 / 4);
    int val = 0, bits = 0;
    for (char c : input) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        unsigned char uc = static_cast<unsigned char>(c);
        int d = kBase64DecodeTable[uc];
        if (d < 0) continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output.push_back(static_cast<char>((val >> bits) & 0xFF));
        }
    }
    return output;
}

// Read a line from connection (up to \n)
std::string readLine(server::IConn& conn) {
    DBG_LOG("readLine: entering");
    std::string line;
    char c;
    while (true) {
        size_t n = conn.Read(reinterpret_cast<uint8_t*>(&c), 1);
        if (n == 0) {
            DBG_LOG("readLine: connection closed", "line_so_far", line);
            break;
        }
        if (c == '\n') break;
        if (c != '\r') line.push_back(c);
    }
    DBG_LOG("readLine: done", "line", line);
    return line;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// HttpServer

void HttpServer::dispatch(std::shared_ptr<server::IConn> conn) {
    try {
        // Read request line
        std::string requestLine = readLine(*conn);
        if (requestLine.empty()) {
            conn->Close();
            return;
        }

        // Parse "CONNECT host:port HTTP/1.1" or "GET http://host/path HTTP/1.1"
        auto space1 = requestLine.find(' ');
        auto space2 = requestLine.find(' ', space1 + 1);
        if (space1 == std::string::npos || space2 == std::string::npos) {
            conn->Close();
            return;
        }

        std::string method = requestLine.substr(0, space1);
        std::string target = requestLine.substr(space1 + 1, space2 - space1 - 1);

        // Read all headers until empty line
        std::string authHeader;
        std::string rawHeaders;
        size_t contentLength = 0;
        while (true) {
            std::string line = readLine(*conn);
            if (line.empty()) break;
            rawHeaders += line + "\r\n";
            if (line.substr(0, 20) == "Proxy-Authorization:") {
                authHeader = line.substr(20);
                size_t start = authHeader.find_first_not_of(" \t");
                if (start != std::string::npos) authHeader = authHeader.substr(start);
            }
            if (line.substr(0, 15) == "Content-Length:") {
                contentLength = static_cast<size_t>(
                    std::stoull(line.substr(15)));
            }
        }

        // Auth check
        if (AuthFunc) {
            auto [user, pass] = parseProxyAuth(authHeader);
            if (!AuthFunc(user, pass)) {
                std::string resp = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                   "Proxy-Authenticate: Basic realm=\"" + AuthRealm + "\"\r\n"
                                   "Content-Length: 0\r\n"
                                   "Connection: close\r\n\r\n";
                conn->Write(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
                conn->Close();
                return;
            }
        }

        if (method == "CONNECT") {
            handleConnect(conn, target);
        } else {
            // Plain HTTP forward proxy: GET/POST/PUT/DELETE/HEAD/OPTIONS etc.
            handleForward(conn, method, target, rawHeaders, contentLength);
        }
    } catch (...) {
        try { conn->Close(); } catch (...) {}
    }
}

bool HttpServer::handleConnect(std::shared_ptr<server::IConn> conn,
                                const std::string& targetAddr) {
    // Log
    if (EventLogger) {
        EventLogger->ConnectRequest("", targetAddr);
    }

    // Dial via Hysteria2 client
    std::shared_ptr<hy2::IByteReaderWriter> rConn;
    try {
        rConn = HyClient->TCP(targetAddr);
    } catch (...) {
        std::string resp = "HTTP/1.1 502 Bad Gateway\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
        conn->Write(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
        if (EventLogger) {
            EventLogger->ConnectError("", targetAddr, "dial failed");
        }
        conn->Close();
        return false;
    }

    // Send 200 Connection Established
    std::string resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
    conn->Write(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());

    // Bidirectional copy
    auto connRw = std::static_pointer_cast<hy2::IByteReaderWriter>(conn);
    server::CopyTwoWay(connRw, rConn);

    if (EventLogger) {
        EventLogger->ConnectError("", targetAddr, "");
    }
    return true;
}

void HttpServer::handleForward(std::shared_ptr<server::IConn> conn,
                                const std::string& method,
                                const std::string& targetUrl,
                                const std::string& rawHeaders,
                                size_t contentLength) {
    if (EventLogger) {
        EventLogger->HTTPRequest("", method + " " + targetUrl);
    }

    // Parse targetUrl (e.g. "http://example.com:80/path") to extract host:port
    std::string dialAddr;
    std::string path = "/";
    {
        // Strip scheme
        std::string url = targetUrl;
        auto schemeEnd = url.find("://");
        if (schemeEnd != std::string::npos) {
            url = url.substr(schemeEnd + 3);
        }
        // Split host and path
        auto pathStart = url.find('/');
        std::string hostPart;
        if (pathStart != std::string::npos) {
            hostPart = url.substr(0, pathStart);
            path = url.substr(pathStart);
        } else {
            hostPart = url;
        }
        // Split host and port
        auto colonPos = hostPart.rfind(':');
        if (colonPos != std::string::npos) {
            dialAddr = hostPart; // already host:port
        } else {
            dialAddr = hostPart + ":80"; // default HTTP port
        }
    }

    // Dial via Hysteria2 client
    std::shared_ptr<hy2::IByteReaderWriter> rConn;
    try {
        rConn = HyClient->TCP(dialAddr);
    } catch (...) {
        std::string resp = "HTTP/1.1 502 Bad Gateway\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
        conn->Write(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
        if (EventLogger) {
            EventLogger->HTTPError("", targetUrl, "dial failed");
        }
        conn->Close();
        return;
    }

    // Rebuild request with path: "GET /path HTTP/1.1\r\nHeaders...\r\n\r\n"
    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n" << rawHeaders << "\r\n";

    std::string reqStr = req.str();
    rConn->Write(reinterpret_cast<const uint8_t*>(reqStr.data()), reqStr.size());

    // Forward request body if present
    if (contentLength > 0) {
        std::vector<uint8_t> body(contentLength);
        size_t got = 0;
        while (got < contentLength) {
            size_t n = conn->Read(body.data() + got, contentLength - got);
            if (n == 0) break;
            got += n;
        }
        if (got > 0) {
            rConn->Write(body.data(), got);
        }
    }

    // Relay the response back to the client
    auto connRw = std::static_pointer_cast<hy2::IByteReaderWriter>(conn);
    server::CopyTwoWay(connRw, rConn);

    if (EventLogger) {
        EventLogger->HTTPError("", targetUrl, "");
    }
}

// ---------------------------------------------------------------------------
// Utility functions

std::string parseHttpRequestTarget(const std::string& requestLine) {
    auto space1 = requestLine.find(' ');
    auto space2 = requestLine.find(' ', space1 + 1);
    if (space1 == std::string::npos || space2 == std::string::npos) return "";
    return requestLine.substr(space1 + 1, space2 - space1 - 1);
}

std::pair<std::string, std::string> parseProxyAuth(const std::string& header) {
    if (header.empty()) return {"", ""};
    // Expect "Basic <base64>"
    if (header.substr(0, 6) != "Basic ") return {"", ""};
    std::string decoded = base64Decode(header.substr(6));
    auto colon = decoded.find(':');
    if (colon == std::string::npos) return {"", ""};
    return {decoded.substr(0, colon), decoded.substr(colon + 1)};
}

} // namespace hy2::proxy::http
