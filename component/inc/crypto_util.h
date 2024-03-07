#ifndef CRYPTO_UTIL_H
#define CRYPTO_UTIL_H

/*
A replacement for the simple_crypto library, utilizing WolfSSL for enhanced encryption and hashing algorithms.

The corresponding implementations are located in crypto_util.c.

For debug printing, this code utilizes the host_messaging library from 2024_MTU_eCTF/2024-ectf-insecure-example/application_processor/inc/host_messaging.h.
*/

#define HASH_LEN 32
#define IV_SIZE 16

#include <stdint.h>
#include <stdlib.h>
#include "general_util.h"

// WolfSSL includes requires the wolfssl library to be installed
#include "wolfssl/wolfcrypt/sha256.h"
#include "wolfssl/wolfcrypt/aes.h"

// Encrypts the content pointed by *in up to len bytes and stores the output in *out. The IV is provided by the caller.
void aes_encrypt(uint8_t *in, uint8_t *out, uint8_t iv[IV_SIZE], size_t len);

// Decrypts the content pointed by *in up to len bytes and stores the output in *out. The IV is provided by the caller.
void aes_decrypt(uint8_t *in, uint8_t *out, uint8_t IV[IV_SIZE], size_t len);

// Computes the SHA-256 hash of the bytes in *in and stores the result in *out.
void hash(uint8_t *in, uint8_t out[HASH_LEN], size_t len);

#endif
