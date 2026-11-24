#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"
#include "types.h"
#include "conversions.h"
#include "decode_ml.h"
#include "kem.h"
#include "ntl.h"
#include "FromNIST/rng.h"

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

static unsigned get_bit(const uint8_t *bits, uint32_t pos)
{
    return (bits[pos >> 3] >> (pos & 7U)) & 1U;
}

static void set_bit(uint8_t *bits, uint32_t pos, unsigned value)
{
    const uint8_t mask = (uint8_t)(1U << (pos & 7U));
    if (value)
        bits[pos >> 3] |= mask;
    else
        bits[pos >> 3] &= (uint8_t)~mask;
}

static void rotate_polynomial(uint8_t out[R_SIZE], const uint8_t in[R_SIZE],
                              uint32_t shift)
{
    memset(out, 0, R_SIZE);
    for (uint32_t i = 0; i < R_BITS; i++) {
        if (get_bit(in, i))
            set_bit(out, (i + shift) % R_BITS, 1);
    }
}

static uint32_t dense_weight(const uint8_t *bits, uint32_t nbits)
{
    uint32_t weight = 0;
    for (uint32_t i = 0; i < nbits; i++)
        weight += bits[i] != 0;
    return weight;
}

static void make_mask(uint8_t c0[R_SIZE], uint32_t weight)
{
    uint16_t positions[R_BITS];
    uint64_t state = UINT64_C(0x243f6a8885a308d3);
    memset(c0, 0, R_SIZE);
    for (uint32_t i = 0; i < R_BITS; i++)
        positions[i] = (uint16_t)i;
    for (uint32_t i = 0; i < weight; i++) {
        uint32_t j = i + (uint32_t)(splitmix64(&state) % (R_BITS - i));
        uint16_t tmp = positions[i];
        positions[i] = positions[j];
        positions[j] = tmp;
        set_bit(c0, positions[i], 1);
    }
}

static void syndrome_from_key(uint8_t sbits[R_BITS], const uint8_t c0[R_SIZE],
                              const sk_t *sk)
{
    uint8_t product[R_SIZE] = {0};
    uint8_t linear[R_BITS] = {0};
    ntl_mod_mul(product, sk->val0, c0);
    convertByteToBinary(linear, product, R_BITS);
    transpose(sbits, linear);
}

int main(int argc, char **argv)
{
    const uint32_t shift =
        argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 0U;
    const uint32_t mask_weight =
        argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 10) : 8U;
    uint8_t seed[48];
    uint8_t pk[sizeof(pk_t)];
    sk_t sk;
    sk_t rotated;
    uint8_t c0[R_SIZE];
    uint8_t sbits[R_BITS];
    uint8_t e_bits[N_BITS];
    uint32_t h0_compact[DV];
    uint32_t h1_compact[DV];
    int rc;

    if (shift >= R_BITS || mask_weight == 0 || mask_weight >= R_BITS) {
        fprintf(stderr, "usage: %s SHIFT[0,%llu] MASK_WEIGHT[1,%llu]\n",
                argv[0], (unsigned long long)(R_BITS - 1U),
                (unsigned long long)(R_BITS - 1U));
        return 2;
    }

    memset(seed, 0x42, sizeof(seed));
    randombytes_init(seed, NULL, 256);
    if (crypto_kem_keypair(pk, (uint8_t *)&sk) != 0)
        return 3;

    rotated = sk;
    rotate_polynomial(rotated.val0, sk.val0, shift);
    rotate_polynomial(rotated.val1, sk.val1, shift);

    make_mask(c0, mask_weight);
    syndrome_from_key(sbits, c0, &rotated);
    const uint32_t initial_weight = dense_weight(sbits, R_BITS);

    convert2compact(h0_compact, rotated.val0);
    convert2compact(h1_compact, rotated.val1);
    memset(e_bits, 0, sizeof(e_bits));
    rc = BGF_decoder(e_bits, sbits, h0_compact, h1_compact);

    printf("shift=%u mask_weight=%u h0_zero=%u h1_zero=%u "
           "initial_syndrome_weight=%u decoder_rc=%d "
           "final_syndrome_weight=%u guess_weight=%u\n",
           shift, mask_weight, get_bit(rotated.val0, 0),
           get_bit(rotated.val1, 0), initial_weight, rc,
           dense_weight(sbits, R_BITS),
           dense_weight(e_bits, N_BITS));
    return 0;
}
