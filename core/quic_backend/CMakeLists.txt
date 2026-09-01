set(QUIC_BACKEND_SOURCES
    ngtcp2_connection.cpp
    ngtcp2_stream.cpp
    ngtcp2_listener.cpp
    udp_socket.cpp
    h3_auth.cpp
    quic_backend_factory.cpp
)

add_library(hy2_quic_backend STATIC ${QUIC_BACKEND_SOURCES})

target_include_directories(hy2_quic_backend
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(hy2_quic_backend
    PUBLIC hy2_core
    PUBLIC hy2_extras
    PUBLIC ngtcp2_static
    PUBLIC ngtcp2_crypto_ossl_static
    PUBLIC nghttp3_static
)

# Link OpenSSL directly using found library paths.
# ngtcp2's find_package(OpenSSL) creates targets in its FetchContent subdirectory
# scope that don't propagate to the parent. We link directly to avoid this issue.
if(DEFINED OPENSSL_SSL_LIBRARY AND DEFINED OPENSSL_CRYPTO_LIBRARY)
    target_link_libraries(hy2_quic_backend PUBLIC "${OPENSSL_SSL_LIBRARY}")
    target_link_libraries(hy2_quic_backend PUBLIC "${OPENSSL_CRYPTO_LIBRARY}")
else()
    # Fallback: try the target if it exists
    if(TARGET OpenSSL::SSL)
        target_link_libraries(hy2_quic_backend PUBLIC OpenSSL::SSL)
    endif()
    if(TARGET OpenSSL::Crypto)
        target_link_libraries(hy2_quic_backend PUBLIC OpenSSL::Crypto)
    endif()
endif()

target_include_directories(hy2_quic_backend PRIVATE
    ${NGTCP2_INCLUDE_DIRS}
    ${NGHTTP3_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_compile_features(hy2_quic_backend PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(hy2_quic_backend PRIVATE /utf-8 /W4 /permissive- /EHsc)
else()
    target_compile_options(hy2_quic_backend PRIVATE -Wall -Wextra)
endif()
