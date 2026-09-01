#!/bin/bash
# run_tests.sh - Compile and run DoH/TFO tests
#
# Usage: ./run_tests.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================================================"
echo "  DoH & TFO Feature Tests"
echo "================================================================"
echo ""

# Check if we're on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "WARNING: TFO tests require Linux"
fi

# Check for required tools
if ! command -v g++ &> /dev/null; then
    echo "Error: g++ not found"
    exit 1
fi

# Compile test (including source files directly)
echo "[1/2] Compiling test..."
g++ -std=c++20 -O2 -o test_doh_tfo test_doh_tfo.cpp \
    ../src/outbounds/dns_outbound.cpp \
    ../src/outbounds/direct.cpp \
    -I../include \
    -I../../core/include \
    -lssl -lcrypto -lpthread

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi
echo "Compilation successful!"
echo ""

# Run test
echo "[2/2] Running tests..."
echo ""
./test_doh_tfo

# Exit with test result
exit $?
