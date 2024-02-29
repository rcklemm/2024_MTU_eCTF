/*
Initially copying this in untouched, this is the core of what we need to update for 
the actual functional & security requirements. Assume our libraries work correctly and 
try to use them here. Whoever does this should also do component.c
*/


/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
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
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"

#include "ap_messaging.h"

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

extern msg_t transmit;
extern msg_t receive;


/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    reset_msg();

    // Initiate handshake
    int result = ap_transmit(address);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive next part of handshake
    result = ap_poll_recv(address, 0);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    // If everything passes up to this point, actually send the message
    // First byte of transmit.contents is len, then transmit.contents[1..] holds
    // the actual message
    transmit.contents[0] = len;
    memcpy(&(transmit.contents[1]), buffer, len);

    return ap_transmit(address);
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    reset_msg();

    // Receive first part, don't check rng challenge
    int result = ap_poll_recv(address, 1);
    if (result != SUCCESS_RETURN) {
        return -1;
    }

    // Send second half of handshake
    ap_transmit(address);

    // Receive last part of handshake, which includes the message
    result = ap_poll_recv(address, 0);
    if (result != SUCCESS_RETURN) {
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

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
    
    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr) {
    // Send message
    int result = ap_transmit(addr);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    result = ap_poll_recv(addr, 0);
    if (result != SUCCESS_RETURN) {
        return ERROR_RETURN;
    }

    return SUCCESS_RETURN;
}

/******************************** COMPONENT COMMS ********************************/

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication

    // Scan scan command to each i2c bus address 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist - 0x36 conflicts with separate device on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }
        
        // Assume component is alive -- get its ID 
        transmit.opcode = COMPONENT_CMD_SCAN;
        
        // Send out command and receive result
        int result = issue_cmd(addr);

        // Success, device is present and we have communicated with it again
        if (result == SUCCESS_RETURN) {
            print_info("F>0x%08x\n", *((uint32_t*) receive.contents));
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components(uint32_t *challenges) {
    int validate_result = SUCCESS_RETURN;

    // Validate each component has the correct ID
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Initiate the handshake with the component, receive first response
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        transmit.opcode = COMPONENT_CMD_VALIDATE;

        int ret = issue_cmd(addr);
        if (ret != SUCCESS_RETURN) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            validate_result = ERROR_RETURN;
            continue;
        }

        // If we get here, we believe the component is valid. Need to send it one more message so 
        // it knows that we are valid
        ret = issue_cmd(addr);
        if (ret != SUCCESS_RETURN) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            validate_result = ERROR_RETURN;
            continue;
        }

        // If we get here, the receive buffer should be holding the component id
        uint32_t id = *((uint32_t*) receive.contents);
        // Save off this component's RNG challenge
        challenges[i] = receive.rng_chal;
        // Check that the result is correct
        if (id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            validate_result = ERROR_RETURN;
        }
    }

    return validate_result;
}

int boot_components(uint32_t *challenges, int validate_result) {
    // Buffers for board link communication
    int boot_result = validate_result;

    // Here, the components are waiting for one more command from us that says "boot"
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Set RNG challenge of receive to saved challenge to trick transmit
        // into replying with the right RNG response for this component
        receive.rng_chal = challenges[i];

        // Set transmit contents to current boot result, so component knows
        // whether it should finish booting or abort
        if (boot_result != SUCCESS_RETURN) {
            *((uint32_t *) transmit.contents) = UINT32_MAX;
        } else {
            *((uint32_t *) transmit.contents) = SUCCESS_RETURN;
        }
        
        // Send out command and receive result
        int ret = issue_cmd(addr);
        if (ret != SUCCESS_RETURN) {
            print_error("Could not boot component 0x%08x\n", flash_status.component_ids[i]);
            boot_result = ERROR_RETURN;
            continue;
        }

        // Here, the component should have echoed our contents, and if successful
        // in booting, the component's boot message should be at contents[4]
        uint32_t comp_boot = *((uint32_t*) receive.contents);
        if (comp_boot == SUCCESS_RETURN) {
            // Print boot message from component
            print_info("0x%08x>%.64s\n", flash_status.component_ids[i], &(receive.contents[4]));
        } else {
            print_error("Could not boot component 0x%08x\n", flash_status.component_ids[i]);
            boot_result = ERROR_RETURN;
        }
    }

    return boot_result;
}

int attest_component(uint32_t component_id) {
    // Check that this is a provisioned comonent
    int provisioned = 0;
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (component_id == flash_status.component_ids[i]) {
            provisioned = 1;
        }
    }
    if (!provisioned) {
        print_error("Cannot attest non-provisioned component\n");
        return ERROR_RETURN;
    }
    
    // Initiate the handshake with the component, receive first response
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);
    transmit.opcode = COMPONENT_CMD_ATTEST;

    int ret = issue_cmd(addr);
    if (ret != SUCCESS_RETURN) {
        print_error("Failed to validate component\n");
        return ERROR_RETURN;
    }

    // If we get here, we believe the component is valid. Need to send it one more message so 
    // it knows that we are valid
    ret = issue_cmd(addr);
    if (ret != SUCCESS_RETURN) {
        print_error("Failed to retrieve attestation data\n");
        return ERROR_RETURN;
    }

    // If we get here, our receive struct should hold the attestation data, so print it to serial
    char attestation_loc[65];
    char attestation_date[65];
    char attestation_cust[65];

    memcpy(attestation_loc, &(receive.contents[0]), 64);
    attestation_loc[64] = '\0';

    memcpy(attestation_date, &(receive.contents[65]), 64);
    attestation_date[64] = '\0';

    memcpy(attestation_cust, &(receive.contents[130]), 64);
    attestation_cust[64] = '\0';

    print_info("C>0x%08x\n", component_id);
    print_info("LOC>%.64s\n", attestation_loc);
    print_info("DATE>%.64s\n", attestation_date);
    print_info("CUST>%.64s\n", attestation_cust);
    print_success("Attest\n");

    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
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

// Compare the entered PIN to the correct PIN
int validate_pin() {
    char buf[50];
    recv_input("Enter pin: ", buf, 50);
    char pin[7];
    strncpy(pin, AP_PIN, 6);
    pin[6] = '\0';

    // Right before the memcmp, pause for random time
    // between 0.5 - 1.5 seconds. Tries to avoid timing attacks
    time_delay(500000, 1500000);
    if ((strlen(buf) == 6) && !secure_memcmp((uint8_t*) buf, (uint8_t*) pin, 6)) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid PIN!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    char buf[50];
    recv_input("Enter token: ", buf, 50);
    char token[17];
    strncpy(token, AP_TOKEN, 16);
    token[16] = '\0';

    // Right before the memcmp, pause for random time
    // between 0.5 - 1.5 seconds. Tries to avoid timing attacks
    time_delay(500000, 1500000);
    if ((strlen(buf) == 16) && !secure_memcmp((uint8_t*) buf, (uint8_t*) token, 16)) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    uint32_t comp_challenges[flash_status.component_cnt];
    int validate_result = validate_components(comp_challenges);
    int boot_result = boot_components(comp_challenges, validate_result);

    if (boot_result != SUCCESS_RETURN) {
        print_error("Boot Failed\n");
        return;
    }

    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    reset_msg();
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        // We are potentially being attacked -- pause 
        // for 4 seconds, set LED to red during the pause
        LED_Off(LED3);
        MXC_Delay(4000000);
        LED_On(LED3);
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf, 50);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf, 50);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[50];

    if (validate_pin()) {
        // We are potentially being attacked -- pause 
        // for 4 seconds, set LED to red during the pause
        LED_Off(LED3);
        MXC_Delay(4000000);
        LED_On(LED3);
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf, 50);
    sscanf(buf, "%x", &component_id);
    attest_component(component_id);
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    // Should be purple in normal operation
    // Turning off LED3 makes red
    LED_On(LED1);
    LED_On(LED3);

    // Handle commands forever
    char buf[100];
    while (1) {
        // Clear out any data that might still be in memory
        reset_msg();

        recv_input("Enter Command: ", buf, 100);

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
