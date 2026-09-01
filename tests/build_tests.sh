#!/bin/bash
# build_tests.sh - Build hy2-cpp tests
#
# Usage:
#   ./build_tests.sh              # Build without QUIC backend (faster)
#   ./build_tests.sh --quic       # Build with QUIC backend (needs OpenSSL)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo "================================================================"
echo "  hy2-cpp Test Builder"
echo "================================================================"
echo ""

# Parse arguments
WITH_QUIC=OFF
for arg in "$@"; do
    case $arg in
        --quic)
            WITH_QUIC=ON
            ;;
    esac
done

# Check if we're on Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Platform: Linux"
    GENERATOR="Ninja"
else
    echo "Platform: Windows"
    GENERATOR="Visual Studio 17 2022"
fi

echo "QUIC Backend: $WITH_QUIC"
echo ""

# Configure
echo "[1/2] Configuring..."
if [[ "$WITH_QUIC" == "ON" ]]; then
    cmake -S "$ROOT_DIR/hy2-cpp" -B "$ROOT_DIR/hy2-cpp/build" \
        -G "$GENERATOR" \
        -DHY2_WITH_QUIC_BACKEND=ON \
        -DOPENSSL_ROOT_DIR=/usr \
        -DOPENSSL_INCLUDE_DIR=/usr/include \
        -DOPENSSL_SSL_LIBRARY=/usr/lib/x86_64-linux-gnu/libssl.so \
        -DOPENSSL_CRYPTO_LIBRARY=/usr/lib/x86_64-linux-gnu/libcrypto.so
else
    cmake -S "$ROOT_DIR/hy2-cpp" -B "$ROOT_DIR/hy2-cpp/build" \
        -G "$GENERATOR" \
        -DHY2_WITH_QUIC_BACKEND=OFF
fi

echo ""
echo "[2/2] Building tests..."

# Build all tests
cmake --build "$ROOT_DIR/hy2-cpp/build" --target hy2_tests -j$(nproc 2>/dev/null || echo 4)

echo ""
echo "================================================================"
echo "  Build complete!"
echo "================================================================"
echo ""
echo "Run tests with:"
echo "  $ROOT_DIR/hy2-cpp/build/tests/hy2_tests"
echo ""
echo "Run filtered tests with:"
echo "  $ROOT_DIR/hy2-cpp/build/tests/hy2_full_test dns"
echo "  $ROOT_DIR/hy2-cpp/build/tests/hy2_full_test platform"
echo ""
