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

# ---- Link-time optimization (LTCG / IPO) for the hy2 targets ----
# Scope: only the four targets this project owns. The vendored third_party
# libraries (ngtcp2, nghttp3, OpenSSL) keep their own build settings - they are
# not ours to change, and a non-LTCG static library links into an LTCG image
# fine; it just cannot be optimized across that boundary.
#
# Only the optimized configurations are touched, so Debug builds stay fast to
# link and debuggable.
#
# Default OFF, deliberately: measured on the loopback benchmark (N=1 and N=8,
# 3 alternating runs each) LTO changed aggregate throughput by less than the
# run-to-run spread (~15% at N=8, ~7% at N=1) - N=1 even came out marginally
# lower. The per-packet cost is dominated by OpenSSL's AEAD and by the sendto
# syscall, neither of which is in a target this can optimize across. So it is
# offered as a switch rather than imposed, and it costs ~2.5x build time.
# Turn it on with -DHY2_ENABLE_LTO=ON.
option(HY2_ENABLE_LTO "Enable interprocedural optimization for hy2 targets" OFF)

if(HY2_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT HY2_IPO_SUPPORTED OUTPUT HY2_IPO_MESSAGE)
    if(HY2_IPO_SUPPORTED)
        foreach(hy2_lto_target hy2_core hy2_extras hy2_app hy2_quic_backend)
            if(TARGET ${hy2_lto_target})
                set_property(TARGET ${hy2_lto_target} PROPERTY
                             INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
                set_property(TARGET ${hy2_lto_target} PROPERTY
                             INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO TRUE)
            endif()
        endforeach()
        message(STATUS "LTO/IPO: enabled for hy2_core/hy2_extras/hy2_app/hy2_quic_backend")
    else()
        message(STATUS "LTO/IPO: not supported by this toolchain (${HY2_IPO_MESSAGE})")
    endif()
endif()

enable_testing()
