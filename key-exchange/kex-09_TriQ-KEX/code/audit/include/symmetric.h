#ifndef AUDIT_SYMMETRIC_H
#define AUDIT_SYMMETRIC_H

#include <stdint.h>

typedef struct {
    unsigned char state[64];
    unsigned long long counter;
} triq_xof_ctx;

void xof_init(triq_xof_ctx *ctx, const uint8_t *seed, unsigned int seed_len);
void xof_get_bytes(triq_xof_ctx *ctx, uint8_t *out, unsigned int out_len);
void hash_h(uint8_t *out, const uint8_t *in);
void hash_g(uint8_t *out, const uint8_t *h, const uint8_t *m,
            const uint8_t *salt);
int crypto_kem_keypair(uint8_t *ek_kem, uint8_t *dk_kem);
int crypto_kem_enc(uint8_t *c_kem, uint8_t *k, const uint8_t *ek_kem);
int crypto_kem_dec(uint8_t *k_prime, const uint8_t *c_kem,
                   const uint8_t *dk_kem);

#endif
