/**
 * @file crypto.h
 * @brief Minimal AES helper prototypes used by the project.
 * 
 * @author Jan Cernoch <xcernoj00>
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/aes.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Encrypt a plaintext buffer using AES-256-CBC.
 *
 * The function allocates a ciphertext buffer and sets *ciphertext to point
 * to it; the caller is responsible for freeing the buffer. The implementation
 * derives a key/IV from the provided key string. Returns non-zero on success.
 *
 * @param plaintext Pointer to input bytes to encrypt.
 * @param plaintext_len Length of plaintext in bytes.
 * @param ciphertext Output pointer which will be set to allocated ciphertext.
 * @param ciphertext_len Output length of ciphertext in bytes.
 * @param key_str Null-terminated key string used to derive AES key/IV.
 * @return 1 on success, 0 on failure.
 */
int aes_encrypt(const uint8_t *plaintext, size_t plaintext_len,
    uint8_t **ciphertext, size_t *ciphertext_len,
    const char *key_str);

/**
 * @brief Decrypt an AES-256-CBC ciphertext buffer.
 *
 * Allocates a plaintext buffer and sets *plaintext to point to it. Caller must
 * free the buffer when done. Returns non-zero on success.
 *
 * @param ciphertext Pointer to ciphertext bytes.
 * @param ciphertext_len Length of ciphertext in bytes.
 * @param plaintext Output pointer which will be set to allocated plaintext.
 * @param plaintext_len Output length of plaintext in bytes.
 * @param key_str Null-terminated key string used to derive AES key/IV.
 * @return 1 on success, 0 on failure.
 */
int aes_decrypt(const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t **plaintext, size_t *plaintext_len,
    const char *key_str);

#endif /* CRYPTO_H */
