#include "crypto_util.h"
#include "host_messaging.h"
#include "global_secrets.h"

#define BLOCK_SIZE 16

// AES key for encryption and decryption
uint8_t key[16] = KEY;

/**
 * @brief Encrypts the input using AES in CBC mode.
 *
 * @param in Pointer to the input data.
 * @param out Pointer to the output buffer where the encrypted data will be stored.
 * @param iv Initialization vector.
 * @param len Length of the input data.
 */
void aes_encrypt(uint8_t *in, uint8_t *out, uint8_t iv[IV_SIZE], size_t len) 
{
    wolfCrypt_Init(); // Initialize wolfSSL
    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE) {
        return; //Invalid length
    }
    Aes aes; // Context for encryption

    wc_AesInit(&aes, NULL, INVALID_DEVID); // Initialize the context

    wc_AesSetKey(&aes, key, sizeof(key), iv, AES_ENCRYPTION); // Set the key and IV
    wc_AesCbcEncrypt(&aes, out, in, len); // Encrypt the input

    wc_AesFree(&aes); // Clean up the context
    wolfCrypt_Cleanup(); // Clean up wolfSSL
}

/**
 * @brief Decrypts the input using AES in CBC mode.
 *
 * @param in Pointer to the input data.
 * @param iv Initialization vector.
 * @param out Pointer to the output buffer where the decrypted data will be stored.
 * @param len Length of the input data.
 */
void aes_decrypt(uint8_t *in, uint8_t *out, uint8_t iv[IV_SIZE], size_t len)
{
    wolfCrypt_Init(); // Initialize wolfSSL
    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE) {
        return; //Invalid length
    }
    Aes aes; // Context for encryption

    wc_AesInit(&aes, NULL, INVALID_DEVID); // Initialize the context

    wc_AesSetKey(&aes, key, sizeof(key), iv, AES_DECRYPTION); // Set the key and IV
    
    wc_AesCbcDecrypt(&aes, out, in, len); // Decrypt the input

    wc_AesFree(&aes); // Clean up the context
    wolfCrypt_Cleanup(); // Clean up wolfSSL
}

/**
 * @brief Computes the SHA-256 hash of the input data.
 *
 * @param in Pointer to the input data.
 * @param out Pointer to the buffer where the hash will be stored.
 * @param len Length of the input data.
 */
void hash(uint8_t *in, uint8_t out[HASH_LEN], size_t len)
{
   Sha256 sha256[1]; // Context for SHA-256
   wc_InitSha256(sha256); // Initialize the SHA-256 context
   wc_Sha256Update(sha256, in, len); // Hash the input
   wc_Sha256Final(sha256, out); // Store the hash in out
}
