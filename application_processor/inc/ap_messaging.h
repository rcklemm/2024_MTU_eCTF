#ifndef AP_MESSAGING_H
#define AP_MESSAGING_H

/*
  Define our messaging struct and routines to send/receive the struct over I2C.
  Depends on our crypto and TRNG utilities in crypto_util / general_util.h
  Also utilizes the I2C send/receive functions defined by board_link.h
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "crypto_util.h"
#include "general_util.h"

// Return values -- match success / failure values from reference design
#define AP_SUCCESS 0
#define AP_FAILURE -1

#define MAX_CONTENTS_LEN 198
#define HASH_LEN 32
#define IV_LEN 16
// Amount of struct, starting from byte 0, that is encrypted
// This means we encrypt from rng_chal up through byte 17 of hash
#define ENC_LEN 224

/* 
   The total size of this struct must be exactly 255 bytes to fit into one
   I2C message. Use the pragma pack compiler directive so that the compiler 
   does not insert padding between fields, which would mess up serialization
*/
#pragma pack(push,1)
typedef struct msg_t {
    // RNG challenge / response values for cryptographic handshake
    uint32_t rng_chal;
    uint32_t rng_resp;
    // Reusing this field from reference design for simplicity
    uint8_t opcode;
    // contents are unencrypted when set by user, encrypted when sent to I2C
    uint8_t contents[MAX_CONTENTS_LEN];
    // Hash of rng_chal through contents, partially encrypted
    uint8_t hash[HASH_LEN];
    // IV used for encryption, always in plaintext
    uint8_t iv[IV_LEN];
} msg_t;
#pragma pack(pop)


// Serialize and send the global transmit msg_t over I2C to the specified address
// User must fill in opcode and contents before calling. This function will handle
// encryption, RNG challenge management, and hashing
int ap_transmit(uint8_t address);

// Receive and deserialize the global receive msg_t over I2C from the specified address
// Fully handles hash check, RNG challenge check, and decryption. Returns success only
// if all checks pass, failure otherwise.
// Set first to nonzero if this is the first message in a sequence, so the RNG response 
// value is not checked (need to be able to initiate a chain somehow).  
int ap_poll_recv(uint8_t address, int first);

// Zero out the global transmit, receive msg_t structs to get confidential data out of 
// device memory. Certainly not strictly necessary, but can't hurt.
void reset_msg();

#endif 
