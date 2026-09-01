file(GLOB_RECURSE HY2_EXTRAS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
if(HY2_EXTRAS_SOURCES)
    add_library(hy2_extras STATIC ${HY2_EXTRAS_SOURCES})
else()
    # Placeholder until extras sources exist
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/extras_dummy.cpp "")
    add_library(hy2_extras STATIC ${CMAKE_CURRENT_BINARY_DIR}/extras_dummy.cpp)
endif()
target_include_directories(hy2_extras PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(hy2_extras PUBLIC cxx_std_20)
target_link_libraries(hy2_extras PUBLIC hy2_core)

# http_outbound and quic_initial unconditionally use OpenSSL, so always link it.
find_package(OpenSSL)
if(NOT OpenSSL_FOUND AND EXISTS "/usr/lib/x86_64-linux-gnu/libssl.so")
    # Ubuntu multiarch fallback
    set(OPENSSL_INCLUDE_DIR "/usr/include" CACHE PATH "" FORCE)
    set(OPENSSL_SSL_LIBRARY "/usr/lib/x86_64-linux-gnu/libssl.so" CACHE FILEPATH "" FORCE)
    set(OPENSSL_CRYPTO_LIBRARY "/usr/lib/x86_64-linux-gnu/libcrypto.so" CACHE FILEPATH "" FORCE)
    find_package(OpenSSL)
endif()
if(OpenSSL_FOUND)
    message(STATUS "extras: Found OpenSSL ${OPENSSL_VERSION}")
    target_link_libraries(hy2_extras PUBLIC OpenSSL::SSL OpenSSL::Crypto)
else()
    message(WARNING "extras: OpenSSL not found - some extras modules will not link")
endif()

# H3 session glue needs the real QUIC backend when enabled.
if(HY2_WITH_QUIC_BACKEND)
    target_link_libraries(hy2_extras PUBLIC hy2_quic_backend)
    target_compile_definitions(hy2_extras PUBLIC HY2_WITH_QUIC_BACKEND=1)
endif()
