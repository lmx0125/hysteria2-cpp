#!/bin/bash
# build.sh - Build hy2-cpp tests
# Usage: ./build.sh

echo "Building hy2-cpp tests..."

if [ ! -d "build" ]; then
    cmake -S . -B build -G Ninja -DHY2_WITH_QUIC_BACKEND=OFF
fi

cmake --build build --target hy2_tests -j$(nproc 2>/dev/null || echo 4)

echo "Done!"
./build/tests/hy2_tests
