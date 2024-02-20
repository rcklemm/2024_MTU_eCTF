/*
True RNG, secure memcmp, time delay functions

Hard part here is figuring out how to use the chip's built-in TRNG function.
The docs are linked somewhere in the Discord, and there's example code sitting somewhere in the MSDK
*/

#include <stdint.h>
#include <stdlib.h>

// Return a random 64-bit value. If it's easier, this could just take in a uint8_t[8] array 
// fill it up instead.
uint64_t rng_gen();

// Pick a random number of microseconds between low and high, sleep the chip that amount of time
// No idea how hard this will be to implement. If there isn't built-in functionality, just do busy waiting
// and query the time constantly in a while-loop
void time_delay(uint32_t low_us, uint32_t high_us);

// Compare the contents of *a and *b up to len bytes
// Do not leave the for-loop early to avoid timing attacks
// Return 0 if equal, nonzero otherwise. Doesn't matter what the nonzero value is
int secure_memcmp(uint8_t *a, uint8_t *b, size_t len);
