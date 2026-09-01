// openssl_mlkem_test.cpp - Minimal test to verify OpenSSL ML-KEM support
// This test does NOT require ngtcp2 or QUIC backend.
#include <cstdio>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "FAIL: SSL_CTX_new returned NULL\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Test 1: Try to set X25519MLKEM768 in supported groups
    int rc = SSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519:P-256:P-384");
    if (rc == 1) {
        printf("PASS: SSL_CTX_set1_groups_list with X25519MLKEM768 succeeded\n");
    } else {
        printf("FAIL: SSL_CTX_set1_groups_list with X25519MLKEM768 returned %d\n", rc);
        ERR_print_errors_fp(stderr);
        // Try without ML-KEM
        ERR_clear_error();
        int rc2 = SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384");
        if (rc2 == 1) {
            printf("INFO: Fallback to X25519:P-256:P-384 succeeded\n");
        } else {
            printf("FAIL: Fallback also failed (%d)\n", rc2);
            ERR_print_errors_fp(stderr);
        }
    }

    // Test 2: Signature algorithms
    rc = SSL_CTX_set1_sigalgs_list(ctx,
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:"
        "ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:"
        "RSA-PSS+SHA512:RSA+SHA512:RSA+SHA1");
    printf("%s: SSL_CTX_set1_sigalgs_list returned %d\n",
           rc == 1 ? "PASS" : "FAIL", rc);
    if (rc != 1) ERR_print_errors_fp(stderr);

    // Test 3: Cipher suites
    rc = SSL_CTX_set_ciphersuites(ctx,
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    printf("%s: SSL_CTX_set_ciphersuites returned %d\n",
           rc == 1 ? "PASS" : "FAIL", rc);
    if (rc != 1) ERR_print_errors_fp(stderr);

    SSL_CTX_free(ctx);
    printf("Done.\n");
    return 0;
}
