#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../original/submission/Implementations/Reference_Implementation/DARTS128/SIG_AlgorithmInstance.h"
#include "../original/submission/Implementations/Reference_Implementation/DARTS128/drng.h"
#include "../original/submission/Implementations/Reference_Implementation/DARTS128/packing.h"
#include "../original/submission/Implementations/Reference_Implementation/DARTS128/params.h"

extern DRNG_ctx drng_algorithm;

static uint64_t read_bits57(const uint8_t *sig, size_t start_bit)
{
    uint64_t value = 0;
    for (size_t bit = 0; bit < 57; bit++) {
        size_t pos = start_bit + bit;
        value |= (uint64_t)((sig[pos / 8] >> (pos % 8)) & 1U) << bit;
    }
    return value;
}

static void write_base17_bits(uint8_t *sig, size_t chunk_start_bit, uint64_t value)
{
    for (size_t bit = 0; bit < 33; bit++) {
        size_t pos = chunk_start_bit + 24 + bit;
        uint8_t mask = (uint8_t)(1U << (pos % 8));
        if ((value >> bit) & 1U) {
            sig[pos / 8] |= mask;
        } else {
            sig[pos / 8] &= (uint8_t)~mask;
        }
    }
}

static int write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return -1;
    }
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

int main(void)
{
    const size_t chunks = 2 * (N / 8);
    const uint64_t base17_cardinality = 6975757441ULL; /* 17^8 */
    const uint64_t base17_bitwidth = 8589934592ULL;    /* 2^33 */
    const size_t lowbits_start_bit = POLY_C_PACKEDBYTES * 8;
    uint8_t seed[48];
    uint8_t msg[32];
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_SIGNATUREBYTES];
    uint8_t mutated[CRYPTO_SIGNATUREBYTES];
    uint8_t corrupted[CRYPTO_SIGNATUREBYTES];
    poly c_original, c_mutated;
    polyvecl low_original, low_mutated, high_original, high_mutated;
    polyveck h_original, h_mutated;
    unsigned long long pk_len = 0, sk_len = 0, sig_len = 0;
    size_t chosen = (size_t)-1;
    uint64_t old_value = 0, new_value = 0;
    size_t changed_bytes = 0;

    memset(seed, 0x55, sizeof(seed));
    memset(msg, 0xa5, sizeof(msg));
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG initialization failed\n");
        return 2;
    }
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
        sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0) {
        fprintf(stderr, "key generation or signing failed\n");
        return 3;
    }
    if (sig_len != CRYPTO_SIGNATUREBYTES) {
        fprintf(stderr, "unexpected signature length: %llu\n", sig_len);
        return 4;
    }
    if (sig_verify(pk, pk_len, sig, sig_len, msg, sizeof(msg)) != 0) {
        fprintf(stderr, "original signature rejected\n");
        return 5;
    }

    for (size_t i = 0; i < chunks; i++) {
        uint64_t block = read_bits57(sig, lowbits_start_bit + i * 57);
        uint64_t base17 = (block >> 24) & ((1ULL << 33) - 1);
        if (base17 < base17_bitwidth - base17_cardinality) {
            chosen = i;
            old_value = base17;
            new_value = base17 + base17_cardinality;
            break;
        }
    }
    if (chosen == (size_t)-1) {
        fprintf(stderr, "no upward-mutable LowBits block in this signature\n");
        return 6;
    }

    memcpy(mutated, sig, sizeof(sig));
    write_base17_bits(mutated, lowbits_start_bit + chosen * 57, new_value);
    for (size_t i = 0; i < sizeof(sig); i++) {
        changed_bytes += sig[i] != mutated[i];
    }
    if (memcmp(sig, mutated, sizeof(sig)) == 0) {
        fprintf(stderr, "mutation did not change serialized signature\n");
        return 7;
    }
    if (sig_verify(pk, pk_len, mutated, sig_len, msg, sizeof(msg)) != 0) {
        fprintf(stderr, "mutated signature rejected\n");
        return 8;
    }
    if (unpack_sig(&c_original, &low_original, &high_original, &h_original, sig) != 0 ||
        unpack_sig(&c_mutated, &low_mutated, &high_mutated, &h_mutated, mutated) != 0) {
        fprintf(stderr, "unpack comparison failed\n");
        return 9;
    }
    int c_equal = memcmp(&c_original, &c_mutated, sizeof(c_original)) == 0;
    int low_equal = memcmp(&low_original, &low_mutated, sizeof(low_original)) == 0;
    int high_equal = memcmp(&high_original, &high_mutated, sizeof(high_original)) == 0;
    int h_equal = memcmp(&h_original, &h_mutated, sizeof(h_original)) == 0;
    if (!c_equal || !low_equal || !high_equal || !h_equal) {
        fprintf(stderr, "mutated signature does not decode identically\n");
        return 10;
    }

    memcpy(corrupted, sig, sizeof(sig));
    corrupted[1000] ^= 1;
    int corrupted_result = sig_verify(pk, pk_len, corrupted, sig_len, msg, sizeof(msg));
    if (corrupted_result == 0) {
        fprintf(stderr, "control corruption unexpectedly accepted\n");
        return 11;
    }

    if (write_file("experiments/repro.pk", pk, (size_t)pk_len) != 0 ||
        write_file("experiments/repro.sig", sig, (size_t)sig_len) != 0 ||
        write_file("experiments/repro.mutated.sig", mutated, (size_t)sig_len) != 0 ||
        write_file("experiments/repro.msg", msg, sizeof(msg)) != 0) {
        fprintf(stderr, "failed to write experiment artifacts\n");
        return 12;
    }

    printf("signature_bytes=%llu\n", sig_len);
    printf("chosen_chunk=%zu\n", chosen);
    printf("old_base17=%llu\n", (unsigned long long)old_value);
    printf("new_base17=%llu\n", (unsigned long long)new_value);
    printf("changed_bytes=%zu\n", changed_bytes);
    printf("raw_equal=%d\n", memcmp(sig, mutated, sizeof(sig)) == 0);
    printf("decoded_c_equal=%d\n", c_equal);
    printf("decoded_lowbits_equal=%d\n", low_equal);
    printf("decoded_highbits_equal=%d\n", high_equal);
    printf("decoded_h_equal=%d\n", h_equal);
    printf("original_verify=0\n");
    printf("mutated_verify=0\n");
    printf("control_verify=%d\n", corrupted_result);
    return 0;
}
