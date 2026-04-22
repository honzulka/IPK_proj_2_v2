/**
 * @file crypto.c
 * @brief Minimal AES helper prototypes used by the project.
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEYLEN 32 // 256 bits
#define AES_IVLEN 16 // 128 bits

// Derive 256-bit key from ASCII string using SHA256
static void derive_key_from_login(const char *key_str, uint8_t *key_out) {
    SHA256((const unsigned char *)key_str, strlen(key_str), key_out);
}

// AES-256-CBC encryption
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
    uint8_t **ciphertext, size_t *ciphertext_len,
    const char *key_str) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int total_len = 0;

    uint8_t key[AES_KEYLEN];
    uint8_t iv[AES_IVLEN];

    // Derive key from login
    derive_key_from_login(key_str, key);

    // Generate random IV
    if (!RAND_bytes(iv, AES_IVLEN)) {
        fprintf(stderr, "Error generating IV\n");
        return 0;
    }

    // Allocate output buffer (IV + encrypted data + possible padding)
    *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE + AES_IVLEN);
    if (!*ciphertext) {
        fprintf(stderr, "malloc failed\n");
        return 0;
    }

    // Copy IV to start
    memcpy(*ciphertext, iv, AES_IVLEN);

    // Create context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Encrypt
    if (EVP_EncryptUpdate(ctx, *ciphertext + AES_IVLEN, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + AES_IVLEN + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *ciphertext_len = AES_IVLEN + total_len; // include IV at start
    return 1;
}

// AES-256-CBC decryption
int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t **plaintext, size_t *plaintext_len,
    const char *key_str) {

    if (ciphertext_len < AES_IVLEN)
        return 0; // too short

    EVP_CIPHER_CTX *ctx;
    int len;
    int total_len = 0;

    uint8_t key[AES_KEYLEN];
    uint8_t iv[AES_IVLEN];

    derive_key_from_login(key_str, key);

    // Extract IV from start
    memcpy(iv, ciphertext, AES_IVLEN);

    // Allocate plaintext buffer
    *plaintext = malloc(ciphertext_len);
    if (!*plaintext)
        return 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext + AES_IVLEN, ciphertext_len - AES_IVLEN) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len = len;

    if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *plaintext_len = total_len;
    return 1;
}
