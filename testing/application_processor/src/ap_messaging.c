#include "ap_messaging.h"
#include "board_link.h"

msg_t transmit, receive;

//this function will be called assuming the global transmit struct
//has opcode and content set, everything else is handled here
int ap_transmit(uint8_t address)
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
    int result = send_packet(address, 255, (uint8_t*) &transmit);
    return result;
}

int ap_poll_recv(uint8_t address) {
    //poll for incoming packet
    int len = poll_and_receive_packet(address, (uint8_t*)&receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }

    //decrypt packet
    uint8_t decryptedData[ENC_LEN];
    aes_decrypt((uint8_t*)&receive, receive.iv, decryptedData, ENC_LEN);
    memcpy((uint8_t*)&receive, decryptedData, ENC_LEN);

    // verify hash
    uint8_t computedHash[HASH_LEN];
    hash((uint8_t*)&receive, computedHash, ENC_LEN); 
    if (memcmp(receive.hash, computedHash, HASH_LEN) != 0) {
        return -1; // Hash mismatch
    }

    // check challenge response
    if (receive.rng_resp != transmit.rng_chal + 1) {
        return -1; // Challenge-response mismatch
    }

    // if all checks pass
    return 0;
}
