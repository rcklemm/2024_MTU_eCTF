/*
Basically a replacement for the simple_crypto library they give us.
Should also use WolfSSL, but implement better encrypt / hash algs.

Implementations go in crypto_util.c

When writing, use the host_messaging library for debug printing (2024_MTU_eCTF/2024-ectf-insecure-example/application_processor/inc/host_messaging.h)
*/

// We will pull this in from somewhere else later
// Program takes in 16 0x0 bytes as the key will need to work more details out later
#define KEY 0x0
#define HASH_LEN 32
#define IV_SIZE 16

// TODO: Other includes that are needed
#include <stdint.h>
#include <stdlib.h>
#include "general_util.h"
#include "dma.h"
#include "aes.h"

// WolfSSL includes requires the wolfssl library to be installed
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>

// Assume in and out are already allocated, encrypt the contents of *in
// up to len bytes and put the output in *out
// Padding??? Do it here, or assume it was already handled
// When we do CBC mode, an IV is generated and sent with the ciphertext.
// Does that get put in *out or should there be another output variable?
// For now, we can just set IV = 0, and fill it in with RNG later
void aes_encrypt(uint8_t *in, uint8_t *out, uint8_t iv[IV_SIZE], size_t len);

// Should be pretty obvious how this works
void aes_decrypt(uint8_t *in, uint8_t iv[IV_SIZE], uint8_t *out, size_t len);

// SHA-256 hash the bytes in *in, put the result into *out
void hash(uint8_t *in, uint8_t out[HASH_LEN], size_t len);