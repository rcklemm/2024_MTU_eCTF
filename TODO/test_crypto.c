#include <stdio.h>
#include "crypto_util.h"
#include <wolfssl/wolfcrypt/sha256.h>

int main() {
    uint8_t input[] = "Hello, world!";
    uint8_t output[HASH_LEN];

    hash(input, output, sizeof(input) - 1); // Pass the input string and its length

    // Print the hash output
    printf("Hash output: ");
    for (int i = 0; i < HASH_LEN; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    return 0;
}
