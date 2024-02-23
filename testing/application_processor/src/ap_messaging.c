#include "ap_messaging.h"
#include "board_link.h"
#include "host_messaging.h"

msg_t transmit, receive;
uint32_t prev_chal;

//this function will be called assuming the global transmit struct
//has opcode and content set, everything else is handled here
int ap_transmit(uint8_t address)
{
    print_debug("entering ap_transmit function\n");
    //gen new challenge, and answer old challenge
    transmit.rng_resp = receive.rng_chal + 1;
    //print_debug("generating challenge\n");
    transmit.rng_chal = (uint32_t) (rng_gen()>>32);
   // print_debug("done generating challenge\n");
    prev_chal = transmit.rng_chal;

    //gen iv
    //print_debug("making IV\n");
    uint64_t randValue;
    randValue = rng_gen();
    memcpy(&transmit.iv[0], &randValue, sizeof(randValue));

    randValue = rng_gen();
    memcpy(&transmit.iv[8], &randValue, sizeof(randValue));
   // print_debug("done making IV\n");

    //gen hash
   // print_debug("starting hash\n");
    hash((uint8_t*)&transmit, transmit.hash, ENC_LEN-1);
    //print_debug("done with hash\n");

    // Encrypt from rng_chal to contents
    // print_debug("starting encryption, struct hex=\n");
    // print_hex((uint8_t*) &transmit, sizeof(msg_t));

    uint8_t encryptedData[ENC_LEN];
    aes_encrypt((uint8_t*)&transmit, encryptedData, transmit.iv, ENC_LEN);
    // Assuming you want to overwrite the original with encrypted data
    memcpy((uint8_t*)&transmit, encryptedData, ENC_LEN);
    
    // print_debug("done with encryption, struct hex=\n");
    // print_hex((uint8_t*) &transmit, sizeof(msg_t));

    //print_debug("calling board_link send_packet function\n");
    //send packet
    int result = send_packet(address, sizeof(msg_t), (uint8_t*) &transmit);
    //print_debug("got result: %d\n", result);
    return result;
}

int ap_poll_recv(uint8_t address) {
    print_debug("ap_poll_recv entered: address = %d\n", address);
    //poll for incoming packet
    int len = poll_and_receive_packet(address, (uint8_t*)&receive);
    print_debug("received len=%d from board_link poll_recv\n", len);
    if (len == 1) {
        return COMPONENT_ALIVE_RET;
    } else if (len != sizeof(msg_t)) {
        return AP_FAILURE;
    }

    // print_debug("struct before decrypt: ");
    // print_hex((uint8_t*)&receive, sizeof(msg_t));

    //decrypt packet
    uint8_t decryptedData[ENC_LEN];
    aes_decrypt((uint8_t*)&receive, decryptedData, receive.iv, ENC_LEN);
    memcpy((uint8_t*)&receive, decryptedData, ENC_LEN);

    // print_debug("struct after decrypt: ");
    // print_hex((uint8_t*)&receive, sizeof(msg_t));

    // verify hash
    uint8_t computedHash[HASH_LEN];
    hash((uint8_t*)&receive, computedHash, ENC_LEN-1); 
    if (memcmp(receive.hash, computedHash, HASH_LEN) != 0) {
        print_debug("hash check failed\n");
        return AP_FAILURE; // Hash mismatch
    }

    // check challenge response
    //print_debug("Last RNG Challenge was: %u, this RNG response is: %u\n", transmit.rng_chal, receive.rng_resp);
    if (receive.rng_resp != (prev_chal + 1)) {
        print_debug("challenge-response check failed\n");
        return AP_FAILURE; // Challenge-response mismatch
    }

    // if all checks pass
    return sizeof(msg_t);
}

void reset_msg()
{
    memset(&transmit, 0, sizeof(msg_t));
    memset(&receive, 0, sizeof(msg_t));
    prev_chal = 0;
}

void struct_debug()
{
    msg_t test;

    test.rng_resp = 0x11111111;
    test.rng_chal = 0x22222222;

    test.opcode = 0x33;

    memset(test.contents, 0x44, MAX_CONTENTS_LEN);

    memset(test.hash, 0x55, HASH_LEN);

    memset(test.iv, 0x66, IV_LEN);

    print_debug("hex of rng_resp: ");
    print_hex((uint8_t*) &(test.rng_resp), 4);

    print_debug("hex of rng_chal: ");
    print_hex((uint8_t*) &(test.rng_chal), 4);

    print_debug("hex of opcode: ");
    print_hex((uint8_t*) &(test.opcode), 1);

    print_debug("hex of contents: ");
    print_hex((uint8_t*) &(test.contents), MAX_CONTENTS_LEN);

    print_debug("hex of hash: ");
    print_hex((uint8_t*) &(test.hash), HASH_LEN);

    print_debug("hex of iv: ");
    print_hex((uint8_t*) &(test.iv), IV_LEN);


    print_debug("hex of full struct: ");
    print_hex((uint8_t*) &(test), sizeof(msg_t));
}
