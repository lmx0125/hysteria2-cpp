# tests/CMakeLists.txt - Build all test executables.

# ---------------------------------------------------------------------------
# Collect all test sources (excluding main files)
# ---------------------------------------------------------------------------
file(GLOB ALL_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

# Separate main files from test sources
set(TEST_MAIN "${CMAKE_CURRENT_SOURCE_DIR}/test_main.cpp")
set(TEST_MAIN_FULL "${CMAKE_CURRENT_SOURCE_DIR}/test_main_full.cpp")

set(TEST_SOURCES "")
foreach(src ${ALL_TEST_SOURCES})
    if(NOT src STREQUAL TEST_MAIN AND NOT src STREQUAL TEST_MAIN_FULL)
        # Skip files that have their own main() and are built as standalone executables
        get_filename_component(_fname ${src} NAME)
        if(_fname MATCHES "^(interop_test|remote_test|youtube_test|benchmark_test|openssl_mlkem_test|official_udp_interop_test|download_test|quic_stats_test|quic_sniff_test)\\.cpp$")
            continue()
        endif()
        list(APPEND TEST_SOURCES ${src})
    endif()
endforeach()

# Common include dirs for all test targets
set(TEST_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/app/include
)

# Common link libs for all test targets
set(TEST_LINK_LIBS hy2_core hy2_extras hy2_app)

# ---------------------------------------------------------------------------
# 1. hy2_tests - Original unit test executable (test_main.cpp)
# ---------------------------------------------------------------------------
add_executable(hy2_tests ${TEST_SOURCES} ${TEST_MAIN})
target_include_directories(hy2_tests PRIVATE ${TEST_INCLUDE_DIRS})
target_link_libraries(hy2_tests PRIVATE ${TEST_LINK_LIBS})
add_test(NAME all COMMAND hy2_tests)

# ---------------------------------------------------------------------------
# 2. hy2_full_test - Unified test runner with filtering support
#    Usage: hy2_full_test [filter]
#    Example: hy2_full_test platform
#             hy2_full_test frag
# ---------------------------------------------------------------------------
add_executable(hy2_full_test ${TEST_SOURCES} ${TEST_MAIN_FULL})
target_include_directories(hy2_full_test PRIVATE ${TEST_INCLUDE_DIRS})
target_link_libraries(hy2_full_test PRIVATE ${TEST_LINK_LIBS})
add_test(NAME full COMMAND hy2_full_test)

# ---------------------------------------------------------------------------
# 3. Individual test executables for quick isolated testing
#    Each links only its own test file + test_main.cpp
# ---------------------------------------------------------------------------

# Core protocol tests
file(GLOB CORE_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/frag_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/protocol_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/bbr_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/brutal_pacer_test.cpp
)
add_executable(hy2_core_tests ${CORE_TEST_SOURCES} ${TEST_MAIN})
target_include_directories(hy2_core_tests PRIVATE ${TEST_INCLUDE_DIRS})
target_link_libraries(hy2_core_tests PRIVATE ${TEST_LINK_LIBS})
add_test(NAME core COMMAND hy2_core_tests)

# Server/Client integration tests
file(GLOB SERVER_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/server_client_test.cpp
)
add_executable(hy2_server_tests ${SERVER_TEST_SOURCES} ${TEST_MAIN})
target_include_directories(hy2_server_tests PRIVATE ${TEST_INCLUDE_DIRS})
target_link_libraries(hy2_server_tests PRIVATE ${TEST_LINK_LIBS})
add_test(NAME server COMMAND hy2_server_tests)

# Extras tests
set(EXTRAS_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/extras_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/obfs_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/acl_engine_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/direct_outbound_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/proxy_outbound_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/udphop_conn_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/traffic_logger_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/dns_outbound_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/lifetime_race_test.cpp
)
if(HY2_WITH_QUIC_BACKEND)
    list(APPEND EXTRAS_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/quic_sniff_test.cpp)
endif()
add_executable(hy2_extras_tests ${EXTRAS_TEST_SOURCES} ${TEST_MAIN})
target_include_directories(hy2_extras_tests PRIVATE ${TEST_INCLUDE_DIRS})
target_link_libraries(hy2_extras_tests PRIVATE ${TEST_LINK_LIBS})
add_test(NAME extras COMMAND hy2_extras_tests)

# Platform abstraction tests
file(GLOB PLATFORM_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/platform_test.cpp
)
add_executable(hy2_platform_tests ${PLATFORM_TEST_SOURCES} ${TEST_MAIN})
target_include_directories(hy2_platform_tests PRIVATE ${TEST_INCLUDE_DIRS})
target_link_libraries(hy2_platform_tests PRIVATE ${TEST_LINK_LIBS})
add_test(NAME platform COMMAND hy2_platform_tests)

# ---------------------------------------------------------------------------
# UDP interop test: direct UDP vs official server
# ---------------------------------------------------------------------------
if(HY2_WITH_QUIC_BACKEND)
    add_executable(hy2_udp_interop_test
        ${CMAKE_CURRENT_SOURCE_DIR}/official_udp_interop_test.cpp
    )
    target_include_directories(hy2_udp_interop_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/app/include
        ${CMAKE_SOURCE_DIR}/core/quic_backend/include
    )
    target_link_libraries(hy2_udp_interop_test PRIVATE
        hy2_core hy2_extras hy2_app hy2_quic_backend
    )
    if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY)
        target_link_libraries(hy2_udp_interop_test PRIVATE "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    endif()
    if(MSVC)
        target_link_libraries(hy2_udp_interop_test PRIVATE ws2_32 crypt32)
    endif()
endif()

# ---------------------------------------------------------------------------
# Interop test: C++ client vs official server
# ---------------------------------------------------------------------------
if(HY2_WITH_QUIC_BACKEND)
    add_executable(hy2_interop_test
        ${CMAKE_CURRENT_SOURCE_DIR}/interop_test.cpp
    )
    target_include_directories(hy2_interop_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/app/include
        ${CMAKE_SOURCE_DIR}/core/quic_backend/include
    )
    target_link_libraries(hy2_interop_test PRIVATE
        hy2_core hy2_extras hy2_app hy2_quic_backend
    )
    if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY)
        target_link_libraries(hy2_interop_test PRIVATE "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    endif()
    if(MSVC)
        target_link_libraries(hy2_interop_test PRIVATE ws2_32 crypt32)
    endif()
endif()

# ---------------------------------------------------------------------------
# Remote node test: C++ client vs remote Hysteria2 servers
# ---------------------------------------------------------------------------
if(HY2_WITH_QUIC_BACKEND)
    add_executable(hy2_remote_test
        ${CMAKE_CURRENT_SOURCE_DIR}/remote_test.cpp
    )
    target_include_directories(hy2_remote_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/app/include
        ${CMAKE_SOURCE_DIR}/core/quic_backend/include
    )
    target_link_libraries(hy2_remote_test PRIVATE
        hy2_core hy2_extras hy2_app hy2_quic_backend
    )
    if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY)
        target_link_libraries(hy2_remote_test PRIVATE "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    endif()
    if(MSVC)
        target_link_libraries(hy2_remote_test PRIVATE ws2_32 crypt32)
    endif()
endif()

# ---------------------------------------------------------------------------
# YouTube test: fetch YouTube homepage via Hysteria2 proxy
# ---------------------------------------------------------------------------
if(HY2_WITH_QUIC_BACKEND)
    add_executable(hy2_youtube_test
        ${CMAKE_CURRENT_SOURCE_DIR}/youtube_test.cpp
    )
    target_include_directories(hy2_youtube_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/app/include
        ${CMAKE_SOURCE_DIR}/core/quic_backend/include
    )
    target_link_libraries(hy2_youtube_test PRIVATE
        hy2_core hy2_extras hy2_app hy2_quic_backend
    )
    if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY)
        target_link_libraries(hy2_youtube_test PRIVATE "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    endif()
    if(MSVC)
        target_link_libraries(hy2_youtube_test PRIVATE ws2_32 crypt32)
    endif()

    # ---------------------------------------------------------------------------
    # Benchmark: throughput measurement
    # ---------------------------------------------------------------------------
    add_executable(hy2_benchmark
        ${CMAKE_CURRENT_SOURCE_DIR}/benchmark_test.cpp
    )
    target_include_directories(hy2_benchmark PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/app/include
        ${CMAKE_SOURCE_DIR}/core/quic_backend/include
    )
    target_link_libraries(hy2_benchmark PRIVATE
        hy2_core hy2_extras hy2_app hy2_quic_backend
    )
    if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY)
        target_link_libraries(hy2_benchmark PRIVATE "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    endif()
    if(MSVC)
        target_link_libraries(hy2_benchmark PRIVATE ws2_32 crypt32)
    endif()

    # ---------------------------------------------------------------------------
    # Download test: large file download + SHA256 verification via QUIC proxy
    # ---------------------------------------------------------------------------
    add_executable(hy2_download_test
        ${CMAKE_CURRENT_SOURCE_DIR}/download_test.cpp
    )
    target_include_directories(hy2_download_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/app/include
        ${CMAKE_SOURCE_DIR}/core/quic_backend/include
    )
    target_link_libraries(hy2_download_test PRIVATE
        hy2_core hy2_extras hy2_app hy2_quic_backend
    )
    if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY)
        target_link_libraries(hy2_download_test PRIVATE "${OPENSSL_SSL_LIBRARY}" "${OPENSSL_CRYPTO_LIBRARY}")
    endif()
    if(MSVC)
        target_link_libraries(hy2_download_test PRIVATE ws2_32 crypt32)
    endif()
endif()

# ---------------------------------------------------------------------------
# 4. Real QUIC backend tests (optional, requires HY2_WITH_QUIC_BACKEND=ON)
# ---------------------------------------------------------------------------
if(HY2_WITH_QUIC_BACKEND)
    set(HY2_REAL_QUIC_DIR "${CMAKE_SOURCE_DIR}/../hy2-test/real_quic")
    if(EXISTS "${HY2_REAL_QUIC_DIR}")
        file(GLOB HY2_REAL_QUIC_SOURCES "${HY2_REAL_QUIC_DIR}/*.cpp")
        add_executable(hy2-real-quic-tests ${HY2_REAL_QUIC_SOURCES})
        target_include_directories(hy2-real-quic-tests PRIVATE
            ${HY2_REAL_QUIC_DIR}
            "${HY2_REAL_QUIC_DIR}/.."
            ${CMAKE_SOURCE_DIR}/core/include
            ${CMAKE_SOURCE_DIR}/extras/include
            ${CMAKE_SOURCE_DIR}/core/quic_backend/include
        )
        if(MSVC)
            target_link_libraries(hy2-real-quic-tests PRIVATE dbghelp)
        endif()
        target_link_libraries(hy2-real-quic-tests PRIVATE
            hy2_core hy2_extras hy2_quic_backend
        )
        add_test(NAME real_quic COMMAND hy2-real-quic-tests)
    endif()

    # Interop tests against the official Hysteria2 binary
    set(HY2_INTEROP_DIR "${CMAKE_SOURCE_DIR}/../hy2-test/interop")
    if(EXISTS "${HY2_INTEROP_DIR}")
        file(GLOB HY2_INTEROP_SOURCES "${HY2_INTEROP_DIR}/01_*.cpp" "${HY2_INTEROP_DIR}/20_*.cpp" "${HY2_INTEROP_DIR}/test_main_interop.cpp")
        add_executable(hy2-interop-tests ${HY2_INTEROP_SOURCES})
        file(GLOB HY2_REVERSE_SOURCES "${HY2_INTEROP_DIR}/02_*.cpp")
        add_executable(hy2-reverse-server ${HY2_REVERSE_SOURCES})
        target_include_directories(hy2-reverse-server PRIVATE
            ${HY2_INTEROP_DIR}
            "${HY2_INTEROP_DIR}/.."
            ${CMAKE_SOURCE_DIR}/core/include
            ${CMAKE_SOURCE_DIR}/extras/include
            ${CMAKE_SOURCE_DIR}/core/quic_backend/include
        )
        if(MSVC)
            target_link_libraries(hy2-reverse-server PRIVATE dbghelp)
        endif()
        target_link_libraries(hy2-reverse-server PRIVATE
            hy2_core hy2_extras hy2_quic_backend
        )
        target_include_directories(hy2-interop-tests PRIVATE
            ${HY2_INTEROP_DIR}
            "${HY2_INTEROP_DIR}/.."
            ${CMAKE_SOURCE_DIR}/core/include
            ${CMAKE_SOURCE_DIR}/extras/include
            ${CMAKE_SOURCE_DIR}/core/quic_backend/include
        )
        if(MSVC)
            target_link_libraries(hy2-interop-tests PRIVATE dbghelp)
        endif()
        target_link_libraries(hy2-interop-tests PRIVATE
            hy2_core hy2_extras hy2_quic_backend
        )
        add_test(NAME interop COMMAND hy2-interop-tests)
    endif()
endif()
