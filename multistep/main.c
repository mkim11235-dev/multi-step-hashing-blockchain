// main.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <inttypes.h>
#include <unistd.h>
#include "swifft.h"

#define SWIFFT_KEY_BYTES 1024   // 1024 bytes key
#define SWIFFT_MSG_BYTES 128    // 128 bytes message input size
#define SWIFFT_HASH_BYTES 64    // 64 bytes output digest size

// Difficulty for mining (leading zeros in hex)
int DIFFICULTY = 3;

// Algo enum
typedef enum { ALG_SHA256, ALG_SHA3_256, ALG_SWIFFT } Algo;

// algo_name function
const char* algo_name(Algo a) {
    switch (a) {
        case ALG_SHA256: return "sha256";
        case ALG_SHA3_256: return "sha3_256";
        case ALG_SWIFFT: return "swifft";
        default: return "unknown";
    }
}

// Convert bytes to hex string
void to_hex(const unsigned char *in, size_t in_len, char *out_hex) {
    const char hexchars[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; ++i) {
        out_hex[2*i] = hexchars[(in[i] >> 4) & 0xF];
        out_hex[2*i + 1] = hexchars[in[i] & 0xF];
    }
    out_hex[2*in_len] = 0;
}

// Compute SHA256 hash hex string
void compute_sha_256_hex(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    to_hex(digest, SHA256_DIGEST_LENGTH, out_hex);
}

// Compute SHA3-256 hash hex string using OpenSSL EVP
void compute_sha3_256_hex(const unsigned char *data, size_t len, char *out_hex) {
    unsigned char digest[32];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
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
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        exit(1);
    }
    EVP_MD_CTX_free(mdctx);
    to_hex(digest, outlen, out_hex);
}

// Convert raw 1024-byte key bytes to HashKey structure used by SwiFFT
void bytes_to_HashKey(const unsigned char *key_bytes, HashKey *key) {
    for (int m = 0; m < M; ++m) {
        for (int j = 0; j < N/W; ++j) {
            for (int w = 0; w < W; ++w) {
                int byte_index = m*(N/W)*W + j*W + w;
                if (byte_index < SWIFFT_KEY_BYTES) {
                    (*key).keyval[m][j][w] = (Z)(key_bytes[byte_index] & 0xFF);
                } else {
                    (*key).keyval[m][j][w] = 0;
                }
            }
        }
    }
    for (int j = 0; j < N/W; ++j) {
        for (int w = 0; w < W; ++w) {
            key->keysum[j][w] = 0;
        }
    }
}

// Serialize HashState (H) to digest bytes (64 bytes digest per SWIFFT spec)
void HashState_to_digest_bytes(const HashState H, unsigned char *digest_out) {
    int pos = 0;
    for (int i = 0; i < Mstate; ++i) {
        for (int j = 0; j < N/W; ++j) {
            if (pos < SWIFFT_HASH_BYTES) {
                digest_out[pos++] = H[i][j];
            }
        }
    }
    while (pos < SWIFFT_HASH_BYTES) {
        digest_out[pos++] = 0;
    }
}

// Compute SWIFFT hash and produce hex string
void compute_swifft_hex(const HashKey key, const unsigned char *msg_bytes, char *out_hex) {
    HashState H;
    HashData data;
    memset(data, 0, sizeof(data));
    memcpy(data, msg_bytes, (SWIFFT_MSG_BYTES < sizeof(data)) ? SWIFFT_MSG_BYTES : sizeof(data));
    memset(H, 0, sizeof(H));
    SwiFFT(key, H, data);
    unsigned char digest[SWIFFT_HASH_BYTES];
    HashState_to_digest_bytes(H, digest);
    to_hex(digest, SWIFFT_HASH_BYTES, out_hex);
}

// Build JSON-like block header string
char *build_header(int index, const char *prev_hash, const char *data, const char *miner_pub, const char *algos) {
    char tmp[4056];
    time_t ts = time(NULL);
    snprintf(tmp, sizeof(tmp), "{\"index\":%d,\"prev\":\"%s\",\"ts\":%ld,\"data\":\"%s\",\"miner\":\"%s\",\"algos\":\"%s\"}",
        index, prev_hash, (long)ts, data, miner_pub, algos);
    return strdup(tmp);
}

// Check if hex string meets difficulty by having required leading '0's
int meet_difficulty(const char *hexstr, int difficulty) {
    for (int i = 0; i < difficulty; ++i) {
        if (hexstr[i] != '0') return 0;
    }
    return 1;
}

// Find nonce for algorithm that meets difficulty
int find_nonce_for_algo(Algo algo, const unsigned char *header, size_t header_len, const HashKey swifft_key, uint64_t max_attempts, uint32_t *out_nonce) {
    char hexout[2 * SWIFFT_HASH_BYTES + 1];
    unsigned char *buff = NULL;
    size_t buff_len;

    const uint64_t progress_interval = 1000000ULL;  // print status every 1 million attempts

    for (uint64_t attempt = 0; (max_attempts == 0) || (attempt < max_attempts); ++attempt) {
        if (attempt % progress_interval == 0) {
            printf("Attempt %" PRIu64 "...\n", attempt);
            fflush(stdout);
        }

        uint32_t n = (uint32_t)(rand() & 0xFFFFFFFF);

        char noncebuf[32];
        snprintf(noncebuf, sizeof(noncebuf), "%" PRIu32, n);

        buff_len = header_len + strlen(noncebuf);
        buff = malloc(buff_len);
        if (!buff) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }
        memcpy(buff, header, header_len);
        memcpy(buff + header_len, noncebuf, strlen(noncebuf));

        if (algo == ALG_SHA256) {
            compute_sha_256_hex(buff, buff_len, hexout);
        }
        else if (algo == ALG_SHA3_256) {
            compute_sha3_256_hex(buff, buff_len, hexout);
        }
        else { // SWIFFT
            unsigned char tmp_sha[SHA256_DIGEST_LENGTH];
            SHA256(buff, buff_len, tmp_sha);

            unsigned char msg_buf[SWIFFT_MSG_BYTES];
            for (size_t i = 0; i < SWIFFT_MSG_BYTES; ++i) {
                msg_buf[i] = tmp_sha[i % SHA256_DIGEST_LENGTH];
            }

            msg_buf[0] ^= (n >> 24) & 0xFF;
            msg_buf[1] ^= (n >> 16) & 0xFF;
            msg_buf[2] ^= (n >> 8) & 0xFF;
            msg_buf[3] ^= n & 0xFF;

            compute_swifft_hex(swifft_key, msg_buf, hexout);
        }

        free(buff);

        if (meet_difficulty(hexout, DIFFICULTY)) {
            *out_nonce = n;
            return 1;
        }
    }
    return 0;
}


// Demo mining of one block requiring two algorithms
int demo_mine_block(const HashKey swifft_key, int index, const char *prev_hash,
                    const char *data, const char *miner_id, Algo algoA, Algo algoB) {
    char algos_str[64];
    snprintf(algos_str, sizeof(algos_str), "%s|%s", algo_name(algoA), algo_name(algoB));
    char *header = build_header(index, prev_hash, data, miner_id, algos_str);
    size_t header_len = strlen(header);

    printf("Mining block %d with algos %s (difficulty %d)...\n", index, algos_str, DIFFICULTY);
    fflush(stdout);

    uint32_t nonceA = 0, nonceB = 0;
    uint64_t max_attempts = 0; // 0 means infinite attempts until success

    time_t t0 = time(NULL);
    if (!find_nonce_for_algo(algoA, (unsigned char*)header, header_len, swifft_key, max_attempts, &nonceA)) {
        fprintf(stderr, "Failed to find nonce for %s within attempts\n", algo_name(algoA));
        free(header);
        return 0;
    }
    time_t t1 = time(NULL);

    if (!find_nonce_for_algo(algoB, (unsigned char*)header, header_len, swifft_key, max_attempts, &nonceB)) {
        fprintf(stderr, "Failed to find nonce for %s within attempts\n", algo_name(algoB));
        free(header);
        return 0;
    }
    time_t t2 = time(NULL);

    printf("Found nonces: %s nonce=%" PRIu32 ", %s nonce=%" PRIu32 "\n", algo_name(algoA), nonceA, algo_name(algoB), nonceB);
    printf("Time: algoA %lds, algoB %lds\n", (long)(t1 - t0), (long)(t2 - t1));
    free(header);
    return 1;
}

int main(int argc, char **argv) {
    srand((unsigned int)time(NULL));

    // Load or generate SWIFFT key bytes (1024 bytes)
    unsigned char swifft_key_bytes[SWIFFT_KEY_BYTES];
    FILE *kf = fopen("swifft_key.bin", "rb");
    if (kf) {
        fread(swifft_key_bytes, 1, SWIFFT_KEY_BYTES, kf);
        fclose(kf);
    } else {
        FILE *wf = fopen("swifft_key.bin", "wb");
        for (int i = 0; i < SWIFFT_KEY_BYTES; ++i) {
            swifft_key_bytes[i] = (unsigned char)(i & 0xFF);
        }
        fwrite(swifft_key_bytes, 1, SWIFFT_KEY_BYTES, wf);
        fclose(wf);
        printf("Generated demo swifft_key.bin (fixed pattern 1024 bytes). You can replace it with random data.\n");
    }

    // Convert bytes to HashKey
    HashKey swifft_key;
    bytes_to_HashKey(swifft_key_bytes, &swifft_key);

    // Genesis previous hash dummy
    char genesis_hash[129];
    memset(genesis_hash, '0', 128);
    genesis_hash[128] = 0;

    DIFFICULTY = 1;  // Adjust difficulty for faster/slower mining

    if (!demo_mine_block(swifft_key, 1, genesis_hash, "hello world txs", "miner_1_pub", ALG_SHA256, ALG_SWIFFT)) {
        fprintf(stderr, "Mining block failed\n");
        return 1;
    } else {
        printf("Block mined (demo). Reduce difficulty to mine multiple blocks.\n");
    }

    return 0;
}
