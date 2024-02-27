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
/**
 * @brief Does a random time delay for the chip
 *
 * @param low_us minium microseconds to wait
 * @param high_us maxmimum microseconds to wait
 */
void time_delay(uint32_t low_us, uint32_t high_us)
{
    uint64_t rnd64;
    // Defines the range for our random number  
    uint32_t difference = high_us - low_us + 1;
    uint32_t delay;

    // Generate the 64 bit number
    rnd64 = rng_gen();

    // Get residue of rnd64 mod difference, add that to low to get a value in range [low, high)
    delay = low_us + (rnd64 % difference);

    // Call chip delay
    MXC_Delay(delay);
}

/**
 * @brief Compares two regions of memory
 *
 * @param a first mem block to compare
 * @param b second mem block to compare
 * @param len how many bytes to compare of each mem block
 */
int secure_memcmp(uint8_t *a, uint8_t *b, size_t len)
{
    uint8_t cmp_status = 0;
    
    //Compares the binary of a and b to each other, only if cmp_status
    //has not changed meaning *a and *b are the same so far. Keeps
    //running to not leak any info
    for(int i = 0; i < len; i++){
        if(a[i] != b[i])
            cmp_status = 1;
    }

    return cmp_status;
}
