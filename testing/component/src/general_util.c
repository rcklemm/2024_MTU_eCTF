#include "general_util.h"

/**
 * @brief   TRNG Generates 64 bits random number
 *
 * @return  A random 64-bit number
 */
uint64_t rng_gen()
{
    uint32_t rnd32_1;
    uint32_t rnd32_2;
    uint64_t rnd64;
    
    MXC_TRNG_Init();                                // Initialize TRNG
    
    rnd32_1 = MXC_TRNG_RandomInt();                // Generate 32-bit number
    rnd32_2 = MXC_TRNG_RandomInt();                // Generate 32-bit number
    
    // Combine the two 32-bit numbers into one 64-bit number
    //rnd32_1 is shifted left by 32 bits, making space for rnd32_2 in the lower 32 bits.
    // Then, the bitwise OR operation combines the two values into a single 64-bit number.
    rnd64 = ((uint64_t)rnd32_1 << 32) | rnd32_2;
    
    MXC_TRNG_Shutdown();                            // Shutdown TRNG engine
    
    return rnd64;
}

void time_delay(size_t low_us, size_t high_us);

int secure_memcmp(uint8_t *a, uint8_t *b, size_t len);
