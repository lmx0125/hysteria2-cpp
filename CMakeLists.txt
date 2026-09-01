cmake_minimum_required(VERSION 3.20)
project(hysteria2-cpp LANGUAGES C CXX VERSION 2.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(MSVC)
    add_compile_options(/utf-8 /W4 /permissive- /EHsc)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra)
endif()

# ---- External dependencies (auto-download via FetchContent) ----
add_subdirectory(third_party)

# ---- Core library ----
add_subdirectory(core)

# ---- QUIC backend (ngtcp2 + nghttp3 + OpenSSL) ----
# Controlled by third_party/CMakeLists.txt; when ON, requires OpenSSL.
if(HY2_WITH_QUIC_BACKEND)
    add_subdirectory(core/quic_backend)
endif()

add_subdirectory(extras)
add_subdirectory(app)
add_subdirectory(tests)
add_subdirectory(bench)

enable_testing()
