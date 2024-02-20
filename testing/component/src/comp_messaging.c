#include "comp_messaging.h"
#include "board_link.h"

msg_t transmit, receive;


void comp_transmit_and_ack()
{
    //gen new challenge, and answer old challenge
    transmit.rng_resp=receive.rng_chal+1;
    transmit.rng_chal=(uint32_t)(rng_gen()>>32);
    
    //gen iv
    uint64_t randValue;
    randValue = rng_gen();
    memcpy(&transmit.iv[0], &randValue, sizeof(randValue));

    randValue = rng_gen();
    memcpy(&transmit.iv[8], &randValue, sizeof(randValue));

    //gen hash
    hash((uint8_t*)&transmit,transmit.hash,ENC_LEN);

    // Encrypt from rng_chal to contents
    uint8_t encryptedData[ENC_LEN];
    aes_encrypt((uint8_t*)&transmit, transmit.iv, encryptedData, ENC_LEN);
    // Assuming you want to overwrite the original with encrypted data
    memcpy((uint8_t*)&transmit, encryptedData, ENC_LEN);

    //send packet
    send_packet_and_ack(256, (uint8_t*)&transmit);
}

int comp_wait_recv(int first)
{
    //poll for incoming packet
    int len = wait_and_receive_packet((uint8_t*)&receive);
    if(len < 256){
        return -1;
    }

    //decrypt packet
    uint8_t decryptedData[ENC_LEN];
    aes_decrypt((uint8_t*)&receive, receive.iv, decryptedData, ENC_LEN);
    memcpy((uint8_t*)&receive, decryptedData, ENC_LEN);

    // verify hash
    uint8_t computedHash[HASH_LEN];
    hash((uint8_t*)&receive, computedHash, ENC_LEN);
    if (memcmp(receive.hash, computedHash, HASH_LEN) != 0) {
        return 1; // Hash mismatch
    }

    // check challenge response
    if (!first && (receive.rng_resp != transmit.rng_chal + 1)) {
        return 1; // Challenge-response mismatch
    }

    // if all checks pass
    return 0;
}

