#include "comp_messaging.h"
#include "board_link.h"

msg_t transmit, receive;
uint32_t prev_chal;

void comp_transmit_and_ack()
{
    //gen new challenge, and answer old challenge
    transmit.rng_resp = receive.rng_chal + 1;
    transmit.rng_chal= (uint32_t) (rng_gen() >> 32);

    prev_chal = transmit.rng_chal;
    
    //gen iv
    uint64_t randValue;
    randValue = rng_gen();
    memcpy(&transmit.iv[0], &randValue, sizeof(randValue));

    randValue = rng_gen();
    memcpy(&transmit.iv[8], &randValue, sizeof(randValue));

    //gen hash
    hash((uint8_t*)&transmit, transmit.hash, ENC_LEN-1);

    //print_debug("comp_transmit: struct before encrypt: ");
    //print_hex((uint8_t*)&transmit, sizeof(msg_t));

    // Encrypt from rng_chal to contents
    uint8_t encryptedData[ENC_LEN];
    aes_encrypt((uint8_t*)&transmit, encryptedData, transmit.iv, ENC_LEN);
    // Assuming you want to overwrite the original with encrypted data
    memcpy((uint8_t*)&transmit, encryptedData, ENC_LEN);

    //print_debug("struct after encrypt: ");
    //print_hex((uint8_t*)&transmit, sizeof(msg_t));

    //send packet
    send_packet_and_ack(sizeof(msg_t), (uint8_t*)&transmit);
}

int comp_wait_recv(int first)
{
    //poll for incoming packet
    //print_debug("comp_wait_recv entered\n");
    int len = wait_and_receive_packet((uint8_t*)&receive);
    //print_debug("len received from i2c library: %d\n", len);
    if(len == sizeof(uint8_t)) {
        //print_debug("len is 1 --> assuming this is the 'are you alive' message from scan\n");
        // Set to scan opcode
        receive.opcode = 1;
        return COMP_MESSAGE_1BYTE;
    } else if (len != sizeof(msg_t)) {
        return COMP_MESSAGE_ERROR;
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
        //print_debug("hash check fail\n");
        return COMP_MESSAGE_ERROR; // Hash mismatch
    }

    // check challenge response
    //print_debug("Last RNG Challenge was: %u, this RNG response is: %u\n", transmit.rng_chal, receive.rng_resp);
    // if (first) {
    //     print_debug("this is the first message of a sequence, so don't need to check RNG here\n");
    // }
    if (!first && (receive.rng_resp != (prev_chal + 1))) {
        //print_debug("challenge-response check fail\n");
        return COMP_MESSAGE_ERROR; // Challenge-response mismatch
    }

    // if all checks pass
    //print_debug("comp_wait_recv passed\n");
    return COMP_MESSAGE_SUCCESS;
}

void reset_msg()
{
    memset(&transmit, 0, sizeof(msg_t));
    memset(&receive, 0, sizeof(msg_t));
    prev_chal = 0;
}
