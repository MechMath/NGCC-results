#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static uint32_t next_u32(uint32_t *state) {
  uint32_t x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
}

int main(int argc, char **argv) {
  unsigned trials = 10000;
  unsigned seed_count;
  unsigned t;
  uint64_t forbidden_slots = 0;
  uint64_t forbidden_nonzero = 0;
  uint64_t weight_errors = 0;
  unsigned forbidden_first;
  unsigned forbidden_limit;

  if (argc > 1)
    trials = (unsigned)strtoul(argv[1], NULL, 10);

  if (N <= 256) {
    printf("mode=%d n=%d tau=%d effective_index_max=255 no_forbidden_middle_range\n",
           COMPASS_SIG_MODE, N, TAU);
    return 0;
  }

  forbidden_first = N / 2;
  forbidden_limit = N - TAU;

  for (t = 0; t < trials; ++t) {
    uint8_t seed[CTILDEBYTES];
    uint32_t state = 0x9e3779b9u ^ (t * 0x85ebca6bu) ^
                     (uint32_t)COMPASS_SIG_MODE;
    poly c;
    unsigned i;
    unsigned weight = 0;

    for (seed_count = 0; seed_count < CTILDEBYTES; ++seed_count)
      seed[seed_count] = (uint8_t)(next_u32(&state) >> 24);

    poly_challenge(&c, seed);
    for (i = 0; i < N; ++i) {
      if (c.coeffs[i] != 0)
        ++weight;
      if (i >= forbidden_first && i < forbidden_limit) {
        ++forbidden_slots;
        if (c.coeffs[i] != 0)
          ++forbidden_nonzero;
      }
    }
    if (weight != TAU)
      ++weight_errors;
  }

  printf("mode=%d n=%d tau=%d trials=%u forbidden_indices=[%u,%u) "
         "forbidden_slots=%llu forbidden_nonzero=%llu weight_errors=%llu\n",
         COMPASS_SIG_MODE, N, TAU, trials, forbidden_first, forbidden_limit,
         (unsigned long long)forbidden_slots,
         (unsigned long long)forbidden_nonzero,
         (unsigned long long)weight_errors);

  return forbidden_nonzero == 0 && weight_errors == 0 ? 0 : 1;
}
