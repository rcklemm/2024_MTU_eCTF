#include "general_util.h"

uint64_t rng_gen();

void time_delay(size_t low_us, size_t high_us);

int secure_memcmp(uint8_t *a, uint8_t *b, size_t len);
