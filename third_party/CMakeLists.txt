include(FetchContent)

# ===========================================================================
# 1. OpenSSL — required when HY2_WITH_QUIC_BACKEND=ON (default ON)
# ===========================================================================
option(HY2_WITH_QUIC_BACKEND "Build ngtcp2-based QUIC backend" ON)

if(HY2_WITH_QUIC_BACKEND)
    # Allow explicit overrides for non-standard OpenSSL layouts
    set(_explicit_openssl FALSE)
    if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY AND DEFINED OPENSSL_INCLUDE_DIR)
        set(_explicit_openssl TRUE)
    endif()

    if(NOT _explicit_openssl)
        find_package(OpenSSL QUIET)

        if(NOT OpenSSL_FOUND)
            message(STATUS "OpenSSL not found, attempting auto-install...")

            if(WIN32)
                # Windows: download prebuilt OpenSSL from slproweb.com
                set(_openssl_win_url "https://slproweb.com/download/Win64OpenSSL-3_5_1.exe")
                set(_openssl_win_installer "${CMAKE_BINARY_DIR}/openssl_installer.exe")
                set(_openssl_win_dir "${CMAKE_BINARY_DIR}/openssl")

                message(STATUS "Downloading OpenSSL for Windows...")
                file(DOWNLOAD "${_openssl_win_url}" "${_openssl_win_installer}"
                    STATUS _dl_status SHOW_PROGRESS)
                list(GET _dl_status 0 _dl_result)

                if(_dl_result EQUAL 0)
                    message(STATUS "Installing OpenSSL to ${_openssl_win_dir}...")
                    execute_process(
                        COMMAND "${_openssl_win_installer}" /VERYSILENT /NORESTART
                                /DIR="${_openssl_win_dir}" /NOOPENSSLSSL /
                        RESULT_VARIABLE _install_result
                        OUTPUT_QUIET ERROR_QUIET
                    )
                    if(_install_result EQUAL 0)
                        # Search for installed OpenSSL
                        foreach(_libsub "lib" "lib/VC/x64/MD")
                            if(EXISTS "${_openssl_win_dir}/${_libsub}/libssl.lib")
                                set(OPENSSL_SSL_LIBRARY "${_openssl_win_dir}/${_libsub}/libssl.lib" CACHE FILEPATH "" FORCE)
                                set(OPENSSL_CRYPTO_LIBRARY "${_openssl_win_dir}/${_libsub}/libcrypto.lib" CACHE FILEPATH "" FORCE)
                                set(OPENSSL_INCLUDE_DIR "${_openssl_win_dir}/include" CACHE PATH "" FORCE)
                                set(OPENSSL_ROOT_DIR "${_openssl_win_dir}" CACHE PATH "" FORCE)
                                message(STATUS "OpenSSL installed at: ${_openssl_win_dir}")
                                break()
                            endif()
                        endforeach()
                        find_package(OpenSSL QUIET)
                        if(OpenSSL_FOUND)
                            set(_explicit_openssl TRUE)
                        endif()
                    endif()
                    file(REMOVE "${_openssl_win_installer}")
                endif()
            else()
                # Linux / macOS: try package manager
                find_program(_apt_exec apt)
                find_program(_yum_exec yum)
                find_program(_dnf_exec dnf)
                find_program(_brew_exec brew)

                if(_apt_exec)
                    message(STATUS "Installing libssl-dev via apt...")
                    execute_process(
                        COMMAND sudo -n apt-get install -y libssl-dev
                        RESULT_VARIABLE _apt_result
                        OUTPUT_QUIET ERROR_QUIET
                    )
                    if(NOT _apt_result EQUAL 0)
                        # Try without sudo (may work in Docker)
                        execute_process(
                            COMMAND apt-get install -y libssl-dev
                            RESULT_VARIABLE _apt_result2
                            OUTPUT_QUIET ERROR_QUIET
                        )
                    endif()
                elseif(_dnf_exec)
                    message(STATUS "Installing openssl-devel via dnf...")
                    execute_process(
                        COMMAND sudo -n dnf install -y openssl-devel
                        RESULT_VARIABLE _dnf_result
                        OUTPUT_QUIET ERROR_QUIET
                    )
                elseif(_yum_exec)
                    message(STATUS "Installing openssl-devel via yum...")
                    execute_process(
                        COMMAND sudo -n yum install -y openssl-devel
                        RESULT_VARIABLE _yum_result
                        OUTPUT_QUIET ERROR_QUIET
                    )
                elseif(_brew_exec)
                    message(STATUS "Installing openssl via brew...")
                    execute_process(
                        COMMAND brew install openssl
                        RESULT_VARIABLE _brew_result
                        OUTPUT_QUIET ERROR_QUIET
                    )
                endif()

                # Re-try find_package after install attempt
                find_package(OpenSSL QUIET)
                if(OpenSSL_FOUND)
                    set(_explicit_openssl TRUE)
                endif()
            endif()
        else()
            set(_explicit_openssl TRUE)
        endif()
    endif()

    if(NOT _explicit_openssl)
        if(WIN32)
            message(FATAL_ERROR
                "OpenSSL 3.2+ is required for the QUIC backend but was not found.\n\n"
                "Auto-install failed. Manual options:\n"
                "  1) vcpkg:  vcpkg install openssl:x64-windows\n"
                "  2) Manual: https://slproweb.com/products/Win32OpenSSL.html\n"
                "  3) Set:    cmake -DOPENSSL_ROOT_DIR=C:/path/to/openssl ..\n"
                "  4) Disable QUIC backend: cmake -DHY2_WITH_QUIC_BACKEND=OFF ..\n"
            )
        else()
            message(FATAL_ERROR
                "OpenSSL 3.2+ is required for the QUIC backend but was not found.\n\n"
                "Auto-install failed. Manual options:\n"
                "  1) sudo apt install libssl-dev (Debian/Ubuntu)\n"
                "  2) sudo dnf install openssl-devel (Fedora)\n"
                "  3) brew install openssl (macOS)\n"
                "  4) cmake -DOPENSSL_ROOT_DIR=/path/to/openssl ..\n"
                "  5) Disable QUIC backend: cmake -DHY2_WITH_QUIC_BACKEND=OFF ..\n"
            )
        endif()
    endif()

    # Ensure imported targets exist (find_package inside FetchContent may not propagate)
    # This must run AFTER FetchContent so we know if find_package created targets.
    # If it didn't (common on Windows with non-standard OpenSSL layouts), create them.

    # --- ngtcp2 (QUIC state machine) ---
    set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
    set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
    set(ENABLE_OPENSSL ON CACHE BOOL "" FORCE)
    set(WITH_OPENSSL ON CACHE BOOL "" FORCE)
    set(WITH_GNUTLS OFF CACHE BOOL "" FORCE)
    set(WITH_WOLFSSL OFF CACHE BOOL "" FORCE)
    set(WITH_BORINGSSL OFF CACHE BOOL "" FORCE)
    set(WITH_PICOTLS OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        ngtcp2
        GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
        GIT_TAG        v1.25.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(ngtcp2)

    # --- ngtcp2 patch: fixed-rate loss-insensitive "Brutal" CC ---------------
    # Hysteria's sender for lossy long-RTT paths: window = rate * srtt and
    # loss never shrinks it.  ngtcp2 has no custom-CC hook, so the algorithm
    # is injected into its sources here (same in-place approach as the
    # nghttp3 patch below; each build tree has its own _deps copy, so this
    # runs once per tree).  The marker string keeps it idempotent across
    # re-configures.  Snippets live in third_party/ngtcp2_brutal/.
    set(_hy2_brutal_dir "${CMAKE_CURRENT_SOURCE_DIR}/ngtcp2_brutal")

    set(_ngtcp2_h "${ngtcp2_SOURCE_DIR}/lib/includes/ngtcp2/ngtcp2.h")
    file(READ "${_ngtcp2_h}" _f)
    if(NOT _f MATCHES "ngtcp2_hy2_brutal_patch")
        file(READ "${_hy2_brutal_dir}/ngtcp2_h.enum.inc" _inc)
        string(REPLACE "NGTCP2_CC_ALGO_BBR = 0x02\n} ngtcp2_cc_algo;"
                       "NGTCP2_CC_ALGO_BBR = 0x02,\n${_inc}} ngtcp2_cc_algo;"
                       _f "${_f}")
        file(READ "${_hy2_brutal_dir}/ngtcp2_h.decl.inc" _inc)
        string(REPLACE "NGTCP2_EXTERN uint64_t ngtcp2_conn_get_cwnd_left2(const ngtcp2_conn *conn);"
                       "NGTCP2_EXTERN uint64_t ngtcp2_conn_get_cwnd_left2(const ngtcp2_conn *conn);\n${_inc}"
                       _f "${_f}")
        file(WRITE "${_ngtcp2_h}" "${_f}")
        message(STATUS "Patched ngtcp2: brutAL CC API (${_ngtcp2_h})")
    endif()

    # The controller lives next to BBR (ngtcp2_bbr.h/.c): that header has the
    # complete ngtcp2_cc_bbr type and is already included by ngtcp2_conn.h.
    set(_ngtcp2_bbr_h "${ngtcp2_SOURCE_DIR}/lib/ngtcp2_bbr.h")
    file(READ "${_ngtcp2_bbr_h}" _f)
    if(NOT _f MATCHES "ngtcp2_hy2_brutal_patch")
        file(READ "${_hy2_brutal_dir}/bbr_h.inc" _inc)
        string(REPLACE "} ngtcp2_cc_bbr;"
                       "} ngtcp2_cc_bbr;\n\n${_inc}\n/* ngtcp2_hy2_brutal_patch */"
                       _f "${_f}")
        file(WRITE "${_ngtcp2_bbr_h}" "${_f}")
    endif()

    set(_ngtcp2_conn_h "${ngtcp2_SOURCE_DIR}/lib/ngtcp2_conn.h")
    file(READ "${_ngtcp2_conn_h}" _f)
    if(NOT _f MATCHES "ngtcp2_hy2_brutal_patch")
        file(READ "${_hy2_brutal_dir}/conn_h.inc" _inc)
        string(REPLACE "  ngtcp2_cc_bbr bbr;"
                       "  ngtcp2_cc_bbr bbr;\n${_inc}/* ngtcp2_hy2_brutal_patch */"
                       _f "${_f}")
        file(WRITE "${_ngtcp2_conn_h}" "${_f}")
    endif()

    set(_ngtcp2_conn_c "${ngtcp2_SOURCE_DIR}/lib/ngtcp2_conn.c")
    file(READ "${_ngtcp2_conn_c}" _f)
    if(NOT _f MATCHES "ngtcp2_hy2_brutal_patch")
        file(READ "${_hy2_brutal_dir}/conn_c.case.inc" _inc)
        string(REPLACE "  case NGTCP2_CC_ALGO_BBR:"
                       "${_inc}\n  case NGTCP2_CC_ALGO_BBR:"
                       _f "${_f}")
        file(READ "${_hy2_brutal_dir}/conn_c.inc" _inc)
        set(_f "${_f}\n/* ngtcp2_hy2_brutal_patch */\n${_inc}")
        file(WRITE "${_ngtcp2_conn_c}" "${_f}")
    endif()

    set(_ngtcp2_bbr_c "${ngtcp2_SOURCE_DIR}/lib/ngtcp2_bbr.c")
    file(READ "${_ngtcp2_bbr_c}" _f)
    if(NOT _f MATCHES "ngtcp2_hy2_brutal_patch")
        file(READ "${_hy2_brutal_dir}/bbr_c.inc" _inc)
        set(_f "${_f}\n/* ngtcp2_hy2_brutal_patch */\n${_inc}")
        file(WRITE "${_ngtcp2_bbr_c}" "${_f}")
    endif()

    # --- nghttp3 (HTTP/3 framing + QPACK) ---
    set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
    set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_DOC OFF CACHE BOOL "" FORCE)
    set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)

    # nghttp3 unconditionally creates "check" and "main" targets that collide
    # with ngtcp2's. Patch them out before building.
    FetchContent_Declare(
        nghttp3
        GIT_REPOSITORY https://github.com/ngtcp2/nghttp3.git
        GIT_TAG        v1.18.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_GetProperties(nghttp3)
    if(NOT nghttp3_POPULATED)
        FetchContent_Populate(nghttp3)
    endif()

    # Patch out problematic targets in nghttp3
    file(READ "${nghttp3_SOURCE_DIR}/CMakeLists.txt" _nghttp3_cmakelists)
    string(REPLACE "enable_testing()\nadd_custom_target(check COMMAND \${CMAKE_CTEST_COMMAND})"
                   "# enable_testing() and check target disabled to avoid collision with ngtcp2"
                   _nghttp3_cmakelists "${_nghttp3_cmakelists}")
    # Also remove tests subdirectory inclusion
    string(REGEX REPLACE "add_subdirectory\\(tests\\)" "# add_subdirectory(tests) - disabled" _nghttp3_cmakelists "${_nghttp3_cmakelists}")
    file(WRITE "${nghttp3_SOURCE_DIR}/CMakeLists.txt" "${_nghttp3_cmakelists}")

    add_subdirectory(${nghttp3_SOURCE_DIR} ${nghttp3_BINARY_DIR} EXCLUDE_FROM_ALL)

    # ngtcp2's find_package(OpenSSL) creates targets in its FetchContent scope.
    # They don't propagate to the parent. Recreate them here if needed.
    if(NOT TARGET OpenSSL::SSL)
        add_library(OpenSSL::SSL INTERFACE IMPORTED GLOBAL)
        set_target_properties(OpenSSL::SSL PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${OPENSSL_SSL_LIBRARY}"
        )
        message(STATUS "Created OpenSSL::SSL imported target (GLOBAL)")
    endif()
    if(NOT TARGET OpenSSL::Crypto)
        add_library(OpenSSL::Crypto INTERFACE IMPORTED GLOBAL)
        set_target_properties(OpenSSL::Crypto PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}"
            INTERFACE_LINK_LIBRARIES "${OPENSSL_CRYPTO_LIBRARY}"
        )
        message(STATUS "Created OpenSSL::Crypto imported target (GLOBAL)")
    endif()

    # Export include dirs to parent scope
    set(NGTCP2_INCLUDE_DIRS
        ${ngtcp2_SOURCE_DIR}/lib/includes
        ${ngtcp2_BINARY_DIR}/lib/includes
        ${ngtcp2_SOURCE_DIR}/crypto/includes
        ${ngtcp2_BINARY_DIR}/crypto/includes
        CACHE INTERNAL ""
    )
    set(NGHTTP3_INCLUDE_DIRS
        ${nghttp3_SOURCE_DIR}/lib/includes
        ${nghttp3_BINARY_DIR}/lib/includes
        CACHE INTERNAL ""
    )
else()
    message(STATUS "QUIC backend DISABLED (HY2_WITH_QUIC_BACKEND=OFF)")
    message(STATUS "  Core protocol tests will use mock QUIC transport.")
    message(STATUS "  To enable: cmake -DHY2_WITH_QUIC_BACKEND=ON ..")
endif()
