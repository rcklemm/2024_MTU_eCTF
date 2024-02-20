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

void time_delay(size_t low_us, size_t high_us)
{
    uint32_t rnd32;
    size_t difference = high_us - low_us;
    float modifier;
    size_t delay;

    //Initialize TRNG
    MXC_TRNG_Init();

    //Generate 32-bit number 
    rnd32 = MXC_TRNG_RandomInt();

    //Remove the divide by zero possiblity and it shouldn't affect code unless large numbers
    if(rnd32 == 0){
        rnd32 = 1;
    }

    //Dividing by the max uint32_t value can be to get the random modifier when multiplied by the difference
    modifier = (rnd32 / 4,294,967,295) * difference;
    //Rounds the modifier and is added to low time to get the delay
    delay = low_us + roundf(modifier);
    
    //Puts the current thread to sleep based on the delay time, and gets it into seconds
    //Going off of this documenttation for thrd_sleep
    //https://en.cppreference.com/w/c/thread/thrd_sleep
    thrd_sleep(&(struct timespec){.tv_sec=delay/1E-6}, NULL);
}

int secure_memcmp(uint8_t *a, uint8_t *b, size_t len);
