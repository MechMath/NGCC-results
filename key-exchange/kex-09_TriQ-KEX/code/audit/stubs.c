#include <stdint.h>
#include <string.h>

#include "api.h"
#include "auxfunc.h"
#include "drng.h"
#include "parameters.h"
#include "parsing.h"
#include "symmetric.h"
#include "triq_pke.h"

DRNG_ctx drng_algorithm;

static uint64_t mix64(uint64_t x)
{
    x ^= x >> 30;
    x *= UINT64_C(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x *= UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}

static void stream_bytes(unsigned char *out, size_t len, uint64_t domain)
{
    uint64_t z = mix64(domain + UINT64_C(0x9e3779b97f4a7c15));
    for (size_t i = 0; i < len; ++i) {
        z = mix64(z + i);
        out[i] = (unsigned char)(z >> 56);
    }
}

void prng_init(const unsigned char *entropy, const unsigned char *personalization,
               unsigned int entropy_len, unsigned int personalization_len)
{
    uint64_t seed = 0;
    for (unsigned int i = 0; i < entropy_len; ++i)
        seed = mix64(seed ^ entropy[i]);
    for (unsigned int i = 0; i < personalization_len; ++i)
        seed = mix64(seed ^ personalization[i]);
    memcpy(drng_algorithm.state, &seed, sizeof seed);
    drng_algorithm.counter = 0;
}

int get_random_number(DRNG_ctx *ctx, unsigned char *out,
                      unsigned long long outlen_bits)
{
    stream_bytes(out, (size_t)(outlen_bits / 8),
                 ctx->counter++ ^ UINT64_C(0x524f4d5f41554449));
    return 0;
}

int pseudoXOF(unsigned long long outlen_bits, const unsigned char *input,
              unsigned long long input_len_bits, unsigned char *out)
{
    uint64_t h = UINT64_C(0xcbf29ce484222325);
    for (size_t i = 0; i < (size_t)(input_len_bits / 8); ++i)
        h = mix64(h ^ input[i]);
    stream_bytes(out, (size_t)(outlen_bits / 8), h);
    return 0;
}

void xof_init(triq_xof_ctx *ctx, const uint8_t *seed, unsigned int seed_len)
{
    uint64_t state = UINT64_C(0x584f465f41554449);
    for (unsigned int i = 0; i < seed_len; ++i)
        state = mix64(state ^ seed[i]);
    memcpy(ctx->state, &state, sizeof state);
    ctx->counter = 0;
}

void xof_get_bytes(triq_xof_ctx *ctx, uint8_t *out, unsigned int out_len)
{
    stream_bytes(out, out_len, ctx->counter++ ^ UINT64_C(0x584f465f4f555450));
}

void hash_h(uint8_t *out, const uint8_t *in)
{
    (void)pseudoXOF(SEED_BYTES * 8, in, PUBLIC_KEY_BYTES * 8, out);
}

void hash_g(uint8_t *out, const uint8_t *h, const uint8_t *m,
            const uint8_t *salt)
{
    uint8_t in[SEED_BYTES + PARAM_SECURITY_BYTES + SALT_BYTES];
    memcpy(in, h, SEED_BYTES);
    memcpy(in + SEED_BYTES, m, PARAM_SECURITY_BYTES);
    memcpy(in + SEED_BYTES + PARAM_SECURITY_BYTES, salt, SALT_BYTES);
    (void)pseudoXOF((SHARED_SECRET_BYTES + SEED_BYTES) * 8, in, sizeof in * 8,
                    out);
}

void triq_pke_keygen(uint8_t *ek_pke, uint8_t *dk_pke, uint8_t *seed)
{
    memcpy(ek_pke, seed, SEED_BYTES);
    for (size_t i = SEED_BYTES; i < PUBLIC_KEY_BYTES; ++i)
        ek_pke[i] = (uint8_t)(seed[i % SEED_BYTES] ^ (uint8_t)i);
    memcpy(dk_pke, seed, SEED_BYTES);
}

void triq_pke_encrypt(ciphertext_pke_t *c_pke, const uint8_t *ek_pke,
                      const uint64_t *m, const uint8_t *theta)
{
    const uint8_t *mb = (const uint8_t *)m;
    memset(c_pke, 0, sizeof *c_pke);
    memcpy(c_pke->u, mb, PARAM_SECURITY_BYTES);
    memcpy(c_pke->u + PARAM_SECURITY_BYTES, ek_pke,
           SEED_BYTES);
    memcpy(c_pke->v, theta, SEED_BYTES);
    c_pke->v[SALT_BYTES] ^= 1;
}

uint8_t triq_pke_decrypt(uint64_t *m, const uint8_t *dk_pke,
                         const ciphertext_pke_t *c_pke)
{
    (void)dk_pke;
    memcpy((uint8_t *)m, c_pke->u, PARAM_SECURITY_BYTES);
    return 0;
}

int crypto_kem_keypair(uint8_t *ek_kem, uint8_t *dk_kem)
{
    uint8_t seed[SEED_BYTES] = {0};
    (void)get_random_number(&drng_algorithm, seed, sizeof seed * 8);
    triq_pke_keygen(ek_kem, dk_kem, seed);
    memcpy(dk_kem, ek_kem, PUBLIC_KEY_BYTES);
    memcpy(dk_kem + PUBLIC_KEY_BYTES, seed, SEED_BYTES);
    memset(dk_kem + PUBLIC_KEY_BYTES + SEED_BYTES, 0x53,
           PARAM_SECURITY_BYTES + SEED_BYTES);
    return 0;
}

int crypto_kem_enc(uint8_t *c_kem, uint8_t *k, const uint8_t *ek_kem)
{
    uint8_t m[PARAM_SECURITY_BYTES] = {0};
    uint8_t salt[SALT_BYTES] = {0};
    uint8_t h[SEED_BYTES] = {0};
    uint8_t kg[SHARED_SECRET_BYTES + SEED_BYTES] = {0};
    ciphertext_kem_t c = {0};
    (void)get_random_number(&drng_algorithm, m, sizeof m * 8);
    (void)get_random_number(&drng_algorithm, salt, sizeof salt * 8);
    hash_h(h, ek_kem);
    hash_g(kg, h, m, salt);
    triq_pke_encrypt(&c.c_pke, ek_kem, (const uint64_t *)m,
                     kg + SHARED_SECRET_BYTES);
    memcpy(c.salt, salt, SALT_BYTES);
    triq_c_kem_to_string(c_kem, &c);
    memcpy(k, kg, SHARED_SECRET_BYTES);
    return 0;
}

int crypto_kem_dec(uint8_t *k_prime, const uint8_t *c_kem,
                   const uint8_t *dk_kem)
{
    ciphertext_kem_t c = {0};
    uint8_t m[PARAM_SECURITY_BYTES] = {0};
    uint8_t h[SEED_BYTES] = {0};
    uint8_t kg[SHARED_SECRET_BYTES + SEED_BYTES] = {0};
    triq_c_kem_from_string(&c.c_pke, c.salt, c_kem);
    (void)triq_pke_decrypt((uint64_t *)m, dk_kem + PUBLIC_KEY_BYTES, &c.c_pke);
    hash_h(h, dk_kem);
    hash_g(kg, h, m, c.salt);
    memcpy(k_prime, kg, SHARED_SECRET_BYTES);
    return 0;
}

void triq_c_kem_to_string(uint8_t *ct, const ciphertext_kem_t *c_kem)
{
    memcpy(ct, c_kem->c_pke.u, sizeof c_kem->c_pke.u);
    memcpy(ct + sizeof c_kem->c_pke.u, c_kem->c_pke.v,
           sizeof c_kem->c_pke.v);
    memcpy(ct + sizeof c_kem->c_pke.u + sizeof c_kem->c_pke.v,
           c_kem->salt, SALT_BYTES);
}

void triq_c_kem_from_string(ciphertext_pke_t *c_pke, uint8_t *salt,
                            const uint8_t *ct)
{
    memcpy(c_pke->u, ct, sizeof c_pke->u);
    memcpy(c_pke->v, ct + sizeof c_pke->u, sizeof c_pke->v);
    memcpy(salt, ct + sizeof c_pke->u + sizeof c_pke->v, SALT_BYTES);
}
