#ifndef AUDIT_DRNG_H
#define AUDIT_DRNG_H

typedef struct {
    unsigned char state[64];
    unsigned long long counter;
} DRNG_ctx;

int get_random_number(DRNG_ctx *ctx, unsigned char *out,
                      unsigned long long outlen_bits);
void prng_init(const unsigned char *entropy, const unsigned char *personalization,
               unsigned int entropy_len, unsigned int personalization_len);

#endif
