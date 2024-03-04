/*
Custom messaging structs & serialization routines. User defines struct msg objects
and these functions handle sending them as an I2C message. We can use the built-in
simple_i2c and board_link libraries as-is, no need to handle that stuff ourselves.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto_util.h"


#define COMP_MESSAGE_ERROR -1
#define COMP_MESSAGE_SUCCESS 0

// Calculate this as MAX_I2C_LEN - (everything that isn't the contents part that is sent over I2C) - 1
#define MAX_CONTENTS_LEN 198
#define HASH_LEN 32
#define IV_LEN 16
#define ENC_LEN 224

#pragma pack(push,1)
typedef struct msg_t {
    // The existing code assumes this exists for telling AP / Components which operation the 
    // message is doing (command_message struct in ap/component .c files)
    uint32_t rng_chal;
    uint32_t rng_resp;
    uint8_t opcode;
    // contents are unencrypted in the struct, encrypted when sent out
    uint8_t contents[MAX_CONTENTS_LEN];

    uint8_t hash[HASH_LEN];
    uint8_t iv[IV_LEN];
} msg_t;
#pragma pack(pop)

// Decrypt the encrypted contents when packing it into the struct
void comp_transmit_and_ack();

// Pack struct to byte array and use the built-in I2C messaging functions to send it out
// Encrypt the contents before passing them to byte array
int comp_wait_recv(int first);

// Zero out the msg structs that live in the data section. This gets confidential data out
// of memory after it is retrieved. Probably not necessary, but doesn't hurt
void reset_msg();
