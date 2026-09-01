// app/src/main.cpp - CLI entry point (rewrite of app/cmd root).
//
// Usage:
//   hy2 version                     - print version
//   hy2 self-test                   - run internal sanity checks
//   hy2 server <config.yaml>        - start server (requires QUIC backend)
//   hy2 client <config.yaml>        - start client (requires QUIC transport)
#include <cstdio>
#include <cstring>
#include <string>

#include "hy2/client.hpp"
#include "hy2/server.hpp"

#ifndef HY2_VERSION
#define HY2_VERSION "dev"
#endif

static int printVersion() {
    std::printf("Hysteria 2 C++ implementation (%s)\n", HY2_VERSION);
    std::printf("Wire protocol compatible with HyNetworks/hysteria v2\n");
    return 0;
}

static int printUsage() {
    std::printf(
        "usage:\n"
        "  hy2 version\n"
        "  hy2 self-test\n"
        "  hy2 server <config.yaml>\n"
        "  hy2 client <config.yaml>\n");
    return 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        return printUsage();
    }
    std::string cmd = argv[1];
    if (cmd == "version") {
        return printVersion();
    }
    if (cmd == "self-test") {
        // Minimal smoke: exercise public config types through validation paths.
        using namespace hy2;
        try {
            client::Config cc;
            cc.ServerAddr = "";
            try {
                cc.VerifyAndFill();
                std::printf("self-test FAILED (empty ServerAddr accepted)\n");
                return 1;
            } catch (const ConfigError&) {
                // expected
            }
        } catch (...) {
            std::printf("self-test FAILED (unexpected exception)\n");
            return 1;
        }
        std::printf("self-test ok\n");
        return 0;
    }
    if (cmd == "server" || cmd == "client") {
        if (argc < 3) {
            std::fprintf(stderr, "%s requires a config file argument\n", cmd.c_str());
            return 1;
        }
        std::fprintf(stderr,
                     "%s: no QUIC transport backend registered in this build.\n"
                     "Link an OpenSSL/MsQuic based backend implementing "
                     "SetGlobalQuicBackend/SetGlobalClientTransport.\n",
                     cmd.c_str());
        return 1;
    }
    return printUsage();
}
