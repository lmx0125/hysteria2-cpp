# bench/CMakeLists.txt - Performance benchmarks for hy2-cpp.
#
# Build:
#   cmake --build <build-dir> --target hy2_bench
#
# Run:
#   ./bench/hy2_bench
#
# These benchmarks test pure computational overhead (no real network I/O).
# They require only hy2_core, hy2_extras, and OpenSSL (for BLAKE2b comparison).

cmake_minimum_required(VERSION 3.20)

# Collect all benchmark sources
file(GLOB BENCH_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_executable(hy2_bench ${BENCH_SOURCES})

target_include_directories(hy2_bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/core/include
    ${CMAKE_SOURCE_DIR}/extras/include
)

target_link_libraries(hy2_bench PRIVATE
    hy2_core
    hy2_extras
)

# Link OpenSSL for BLAKE2b comparison benchmark
# Try standard find first, then fall back to manual path
find_package(OpenSSL QUIET)
if(NOT OPENSSL_FOUND)
    # Manual search for OpenSSL on Windows
    find_path(OPENSSL_INCLUDE_DIR openssl/evp.h
        PATHS "C:/Program Files/OpenSSL-Win64/include"
              "C:/Program Files/OpenSSL/include"
        NO_DEFAULT_PATH)
    find_library(OPENSSL_CRYPTO_LIBRARY
        NAMES libcrypto libcrypto_static libcrypto-3-x64
        PATHS "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MT"
              "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD"
              "C:/Program Files/OpenSSL-Win64/lib"
              "C:/Program Files/OpenSSL/lib"
        NO_DEFAULT_PATH)
    if(OPENSSL_INCLUDE_DIR AND OPENSSL_CRYPTO_LIBRARY)
        set(OPENSSL_FOUND TRUE)
        set(OPENSSL_VERSION "4.0.1")
    endif()
endif()

if(OPENSSL_FOUND)
    message(STATUS "bench: OpenSSL found (${OPENSSL_VERSION}) - enabling BLAKE2b EVP comparison")
    message(STATUS "bench: OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "bench: OpenSSL crypto lib: ${OPENSSL_CRYPTO_LIBRARY}")
    target_compile_definitions(hy2_bench PRIVATE HY2_BENCH_HAS_OPENSSL=1)
    target_include_directories(hy2_bench PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(hy2_bench PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
else()
    message(STATUS "bench: OpenSSL not found - BLAKE2b EVP benchmarks will be skipped")
endif()

set_target_properties(hy2_bench PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    OUTPUT_NAME "hy2_bench"
)

# Release mode recommended for meaningful benchmarks
if(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "NOTE: For best benchmark accuracy, build with -DCMAKE_BUILD_TYPE=Release")
endif()
