/*
Custom messaging structs & serialization routines. User defines struct msg objects
and these functions handle sending them as an I2C message. We can use the built-in
simple_i2c and board_link libraries as-is, no need to handle that stuff ourselves.
*/

// TODO: Other includes
#include <stdint.h>
#include <stdlib.h>
#include "crypto_util.h"


// Calculate this as MAX_I2C_LEN - (everything that isn't the contents part that is sent over I2C) - 1
#define MAX_CONTENTS_LEN 180
#define HASH_LEN 32
#define IV_LEN 16

typedef struct msg_t {
    // The existing code assumes this exists for telling AP / Components which operation the 
    // message is doing (command_message struct in ap/component .c files)
    uint8_t opcode;

    uint64_t rng_chal;
    uint64_t rng_resp;

    // contents are unencrypted in the struct, encrypted when sent out
    uint8_t actual_content_len;
    uint8_t contents[MAX_CONTENTS_LEN];

    uint8_t iv[IV_LEN];
    
    uint8_t hash[HASH_LEN];

    // I was thinking there would be some sort of type here, but I think the user can keep track
    // of which message is which for simplicity in the library
} msg_t;

// Use the built-in I2C messaging functions to receive a message and pack it into the struct
// be careful about buffer overflows. We can't assume that the input here will be well-formed
// User needs to specify address.
// Decrypt the encrypted contents when packing it into the struct
void recv_i2c(uint8_t address, msg_t *m);

// Pack struct to byte array and use the built-in I2C messaging functions to send it out
// User needs to specify address.
// Encrypt the contents before passing them to byte array
void send_i2c(uint8_t address, msg_t *m);

// Check that the rng_resp in *b is valid for the rng_chal from *a
// Return 0 if it fails, 1 otherwise
int verify_msg(msg_t *a, msg_t *b);
