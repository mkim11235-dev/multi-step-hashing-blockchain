// main.c
// Multi-step PoW demo in C using SWIFFT (micciancio/SWIFFT) + OpenSSL
//
// Compile with: gcc -O3 -o multistep main.c swifft.c setup.c -lcrypto -lm
//
// Notes:
// - This code uses SwiFFT(key, H, M) from the SWIFFT repo (swifft.c, setup.c).
// - Make sure swifft.c, swifft.h, setup.c are from the micciancio/SWIFFT repo.

// gcc miner.c -o miner \
//   -I/usr/local/opt/openssl/include \
//   -L/usr/local/opt/openssl/lib \
//   -lcrypto -lssl
// /opt/homebrew/opt/openssl@3

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <inttypes.h>
#include <unistd.h>
#include "swifft.h" // from SWIFFT repo


#define SWIFFT_KEY_BYTES 128
#define SWIFFT_HASH_BYTES 72
#define SWIFFT_DATA_BYTES 56

int DIFFICULTY = 3;

typedef enum { ALG_SHA256, ALG_SHA3_256, ALG_SWIFFT } Algo;

const char*algo_name(Algo a) {
    switch (a) {
        case ALG_SHA256: return "sha256";
        case ALG_SHA3_256: return "sha3_256";
        case ALG_SWIFFT: return "swifft";
        default: return "unknown";
    }
}
//convert bytes to hex string
void to_hex(const unsigned char *in, size_t in_len, char *out_hex) {
    const char hexchars[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; ++i) {
        out_hex[2*i] = hexchars[(in[i] >> 4) &0xF];
        out_hex[2*i+1] = hexchars[in[i] & 0xF];
    }
    out_hex[2*in_len] = 0;
}
// given input data, calculates the sha 256 hash and converts to human readable form.
void compute_sha_256_hex(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    to_hex(digest, SHA256_DIGEST_LENGTH, out_hex);
}
//compute sha3 using openssl EVP API
void compute_sha3_256_hex(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char digest[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        exit(1);
    }
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha3_256(), NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        exit(1);
    }
    if (1 != EVP_DigestUpdate(mdctx, data, len)) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        exit(1);
    }
    unsigned int outlen = 0;
    if (1 != EVP_DigestFinal_ex(mdctx, digest, &outlen)) {
        fprintf(stderr,  "EVP_DigestFinal_ex failed \n");
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);
    to_hex(digest, outlen, out_hex);
}
//Define SWIFFT compression function