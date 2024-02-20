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
 * @brief Does a random time delay for the current thread
 *
 * @param low_us minium microseconds to wait
 * @param high_us maxmimum microseconds to wait
 */
void time_delay(uint32_t low_us, uint32_t high_us)
{
    uint64_t rnd64;
    uint32_t difference = high_us - low_us;
    float modifier;
    uint32_t delay;

    //Generate the 64 bit number
    rnd64 = rng_gen();

    //Remove the divide by zero possiblity and it shouldn't affect code unless large numbers
    if(rnd64 == 0){
        rnd64 = 1;
    }

    //Finds the modifier by using rnd64 / UINTMAX_MAX to get a 0-1 num and multiplies it by the difference
    modifier = (rnd64 / UINTMAX_MAX) * difference;

    //Rounds the modifier and is added to low time to get the delay then delays the device
    delay = low_us + roundf(modifier);
    MXC_Delay(delay);
}

/**
 * @brief Does a random time delay for the current thread
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
        if(a[i] > b[i] && status == 0)
            cmp_status = 1;
        else if (*a[i] < *b[i] && status == 0)
            cmp_status = -1;
    }

    return cmp_status;
}
