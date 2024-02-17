#include "crypto_util.h"


//plaeceholder key for testing
//int key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

BLOCK_SIZE = 16;


void aes_encrypt(uint8_t *in, uint8_t *out, uint8_t iv[IV_SIZE], size_t len) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return; //Invalid length

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, 16, &iv, AES_ENCRYPTION);
    if (result != 0) {
        printf("result: %d\n", result);
        return; //Failed to Initialize
    }
    // Encrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, out + i, in + i);
        printf(result);
        if (result != 0)
            return; //Failed to encrypt
    }
    return;
}
// Should be pretty obvious how this works
void aes_decrypt(uint8_t *in, uint8_t iv[IV_SIZE], uint8_t *out, size_t len)
{
    Aes ctx; // Context for encryption
    int result; // Library result
    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return; //Invalid length

    result = wc_AesSetKey(&ctx, key, 16, &iv, AES_DECRYPTION);
    if (result != 0)
        return; //Failed to Initialize

    // Encrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, out + i, in + i); //Decrypt each block
        if (result != 0)
            return; // Failed to decrypt
    }
    return;
}

// SHA-256 hash the bytes in *in, put the result into *out
void hash(uint8_t *in, uint8_t out[HASH_LEN], size_t len)
{
   Sha256 sha256[1]; // Context for SHA-256
   wc_InitSha256(sha256); // Initialize the SHA-256 context
   wc_Sha256Update(&sha256, in, len); // Hash the input
   wc_Sha256Final(&sha256, out); // Store the hash in out
}