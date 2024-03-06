#ifndef GENERAL_UTIL_H
#define GENERAL_UTIL_H

/*
True RNG, secure memcmp, time delay functions

Hard part here is figuring out how to use the chip's built-in TRNG function.
The docs are linked somewhere in the Discord, and there's example code sitting somewhere in the MSDK
*/

#include <stdint.h>
#include <stdlib.h>
#include "mxc_device.h"
#include "nvic_table.h"
#include "mxc_delay.h"
#include "trng.h"

// Generates a random 64-bit value from the onboard TRNG generator.
uint64_t rng_gen();

// Picks a random number of microseconds between low and high, and puts the chip to sleep
// for that amount of time
void time_delay(uint32_t low_us, uint32_t high_us);

// Compare the contents of *a and *b up to len bytes.
// Return 0 if equal, returns 1 if unequal
int secure_memcmp(uint8_t *a, uint8_t *b, size_t len);

#endif
