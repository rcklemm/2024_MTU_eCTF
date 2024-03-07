/**
 * @file component.c
 * @author Jacob Doll 
 * @brief eCTF Component Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_errors.h"
#include "nvic_table.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "simple_i2c_peripheral.h"
#include "board_link.h"

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

#include "comp_messaging.h"

#ifdef POST_BOOT
#include "led.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

/******************************** TYPE DEFINITIONS ********************************/
// Commands received by Component using 32 bit integer
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;


/********************************* FUNCTION DECLARATIONS **********************************/
// Core function definitions
void component_process_cmd(void);
void process_scan(void);
void process_validate(void);
void process_attest(void);

/********************************* GLOBAL VARIABLES **********************************/
// Global messaging strucs from comp_messaging.c
extern msg_t transmit;
extern msg_t receive;

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
void secure_send(uint8_t* buffer, uint8_t len) {
    reset_msg();
    
    // Initiate handshake
    comp_transmit_and_ack();

    // Receive next part of handshake
    int result = comp_wait_recv(0);
    if (result != COMP_MESSAGE_SUCCESS) {
        return;
    }

    // If everything passes up to this point, actually send the message
    // First byte of transmit.contents is len, then transmit.contents[1..] holds
    // the actual message
    transmit.contents[0] = len;
    memcpy(&(transmit.contents[1]), buffer, len);

    comp_transmit_and_ack();
}

/**
 * @brief Secure Receive
 * 
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(uint8_t* buffer) {
    reset_msg();

    // Receive first part, don't check rng challenge 
    int result = comp_wait_recv(1);
    if (result != COMP_MESSAGE_SUCCESS) {
        return -1;
    }

    // Send second half of handshake
    comp_transmit_and_ack();

    // Receive last part of handshake, which includes the message
    result = comp_wait_recv(0);
    if (result != COMP_MESSAGE_SUCCESS) {
        return -1;
    }
    
    // Length is at first byte of contents
    uint8_t len = receive.contents[0];
    // Cap length according to detailed specifications
    if (len > 64) {
        return -1;
    }

    memcpy(buffer, &(receive.contents[1]), len);
    return len;
}

/******************************* FUNCTION DEFINITIONS *********************************/

// Example boot sequence
// Your design does not need to change this
void boot() {
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Anything after this macro can be changed by your design
    // but will not be run on provisioned systems
    LED_Off(LED1);
    LED_Off(LED2);
    LED_Off(LED3);
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

// Handle a transaction from the AP
void component_process_cmd() {
    // Figure out which command we were sent
    switch (receive.opcode) {
        case COMPONENT_CMD_SCAN:
            process_scan();
            break;
        // Our design combines validate + boot into one continuous message sequence
        // between AP and Component, so VALIDATE here is essentially BOOT
        case COMPONENT_CMD_VALIDATE:
            process_validate();
            break;
        case COMPONENT_CMD_ATTEST:
            process_attest();
            break;
        default:
            printf("Error: Unrecognized command received %d\n", receive.opcode);
            // The AP will still be expecting a response if this component is on the I2C bus, 
            // so send them garbage to avoid the whole MISC freezing up
            comp_transmit_and_ack();
            break;
    }
}

void process_scan() {    
    // The AP requested a scan. Respond with the Component ID
    *((uint32_t *) transmit.contents) = COMPONENT_ID;
    
    comp_transmit_and_ack();
}

void process_validate() {
    // Need to respond to show AP we are valid
    comp_transmit_and_ack();

    // Now, wait for another message from the AP. Make sure to validate the challenge-response
    int ret = comp_wait_recv(0);
    if (ret != COMP_MESSAGE_SUCCESS) {
        // Send garbage back to AP to clean out i2c, then return
        *((uint32_t *) transmit.contents) = 0;
        comp_transmit_and_ack();
        return;
    }
    // Send back the component's ID
    *((uint32_t *) transmit.contents) = COMPONENT_ID;
    comp_transmit_and_ack();

    // Now, wait for AP to tell us whether full boot is OK
    ret = comp_wait_recv(0);
    if (ret != COMP_MESSAGE_SUCCESS) {
        // Send garbage back to AP to clean out i2c, then return
        *((uint32_t *) transmit.contents) = 1;
        comp_transmit_and_ack();
        return;
    }

    // Check whether boot is OK
    uint32_t boot_res = *((uint32_t *) receive.contents);
    if (boot_res == 0) {
        // Echo boot success, send boot message, and actually boot
        *((uint32_t *) transmit.contents) = boot_res;
        strncpy((char*) &(transmit.contents[4]), COMPONENT_BOOT_MSG, 64);
        transmit.contents[68] = '\0';
        comp_transmit_and_ack();
        boot();
    } else {
        // Echo boot failure
        *((uint32_t *) transmit.contents) = boot_res;
        comp_transmit_and_ack();
    }
}

void process_attest() {
    // Need to respond to show AP we are valid
    comp_transmit_and_ack();

    // Now, wait for another message from the AP. Make sure to validate the challenge-response
    int ret = comp_wait_recv(0);
    if (ret != COMP_MESSAGE_SUCCESS) {
        // Send garbage back to AP to clean out i2c, then return
        comp_transmit_and_ack();
        return;
    }

    // If we get here, this is a valid AP requesting attestation, so respond with our actual data
    // Be careful on memory movement and null terminating
    // These casts are fine, it just removes some warnings from compiler
    strncpy((char*) &(transmit.contents[0]), ATTESTATION_LOC, 64);
    transmit.contents[64] = 0;
    strncpy((char*) &(transmit.contents[65]), ATTESTATION_DATE, 64);
    transmit.contents[129] = 0;
    strncpy((char*) &(transmit.contents[130]), ATTESTATION_CUSTOMER, 64);
    transmit.contents[194] = 0;

    comp_transmit_and_ack();
}

/*********************************** MAIN *************************************/

int main(void) {
    printf("Component Started\n");
    
    // Enable Global Interrupts
    __enable_irq();
    
    // Initialize Component
    i2c_addr_t addr = component_id_to_i2c_addr(COMPONENT_ID);
    board_link_init(addr);
    

    LED_On(LED2);
    while (1) {
        // Clear out any data that might still be in memory
        reset_msg();

        // Wait for a message from the AP
        int res = comp_wait_recv(1);
        if (res != COMP_MESSAGE_SUCCESS) {
            // If this message is malformed somehow, ensure the opcode
            // does not send us down some valid code path
            receive.opcode = COMPONENT_CMD_NONE;
        }

        // Process the AP's message
        component_process_cmd();
    }
}
