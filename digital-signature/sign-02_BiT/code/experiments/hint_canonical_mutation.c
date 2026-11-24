#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

static void decode_five_trits(int out[5], unsigned int byte) {
    for (int i = 0; i < 5; i++) {
        out[i] = (int)(byte % 3U) - 1;
        byte /= 3U;
    }
}

static size_t differing_bytes(const unsigned char *a, const unsigned char *b,
                              size_t len) {
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        count += a[i] != b[i];
    }
    return count;
}

static int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) return -1;
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

int main(int argc, char **argv) {
    const char *outdir = (argc > 1) ? argv[1] : ".";
    unsigned char seed[55];
    const unsigned char msg[] =
        "BiT hint canonicality experiment: one accepted signature, two encodings.";
    unsigned char pk[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES];
    unsigned char mutated[BIT_SIGNBYTES];
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig_len = 0;
    unsigned int eligible = 0;
    unsigned int accepted_mutations = 0;
    int first_offset = -1;
    unsigned int first_old = 0;
    unsigned int first_new = 0;
    int old_trits[5] = {0};
    int new_trits[5] = {0};
    int decoded_equal = -1;
    int negative_control_rc = -999;
    size_t mutation_differences = 0;
    char path[512];

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0xA5U + 17U * 512U + 31U * 11U + i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;
    if (sig_sign(sk, sk_len, (unsigned char *)msg, sizeof(msg) - 1,
                 sig, &sig_len) != 0) return 4;
    if (sig_verify(pk, pk_len, sig, sig_len,
                   (unsigned char *)msg, sizeof(msg) - 1) != 0) return 5;

    const size_t hint_offset = (size_t)sig_len - BIT_POLYVECK_H_BYTES;
    for (size_t i = hint_offset; i < (size_t)sig_len; i++) {
        if ((unsigned int)sig[i] + 243U > 255U) continue;
        eligible++;
        memcpy(mutated, sig, (size_t)sig_len);
        mutated[i] = (unsigned char)(sig[i] + 243U);
        if (sig_verify(pk, pk_len, mutated, sig_len,
                       (unsigned char *)msg, sizeof(msg) - 1) == 0) {
            accepted_mutations++;
            if (first_offset < 0) {
                first_offset = (int)i;
                first_old = sig[i];
                first_new = mutated[i];
            }
        }
    }

    snprintf(path, sizeof(path), "%s/pk.bin", outdir);
    if (write_file(path, pk, (size_t)pk_len) != 0) return 6;
    snprintf(path, sizeof(path), "%s/message.bin", outdir);
    if (write_file(path, msg, sizeof(msg) - 1) != 0) return 7;
    snprintf(path, sizeof(path), "%s/sig.bin", outdir);
    if (write_file(path, sig, (size_t)sig_len) != 0) return 8;

    if (first_offset >= 0) {
        memcpy(mutated, sig, (size_t)sig_len);
        mutated[first_offset] = (unsigned char)first_new;
        mutation_differences = differing_bytes(sig, mutated, (size_t)sig_len);
        decode_five_trits(old_trits, first_old);
        decode_five_trits(new_trits, first_new);
        decoded_equal = memcmp(old_trits, new_trits, sizeof(old_trits)) == 0;

        if (first_old + 1U <= 255U) {
            unsigned char negative[BIT_SIGNBYTES];
            memcpy(negative, sig, (size_t)sig_len);
            negative[first_offset] = (unsigned char)(first_old + 1U);
            negative_control_rc = sig_verify(
                pk, pk_len, negative, sig_len,
                (unsigned char *)msg, sizeof(msg) - 1);
        }

        snprintf(path, sizeof(path), "%s/sig_noncanonical.bin", outdir);
        if (write_file(path, mutated, (size_t)sig_len) != 0) return 9;
    }

    printf("algorithm=%s\n", ALGORITHM_INSTANCE);
    printf("pk_len=%llu sk_len=%llu sig_len=%llu\n", pk_len, sk_len, sig_len);
    printf("hint_offset=%zu hint_bytes=%d eligible_plus_243=%u accepted_mutations=%u\n",
           hint_offset, BIT_POLYVECK_H_BYTES, eligible, accepted_mutations);
    printf("first_offset=%d old_byte=%u new_byte=%u\n",
           first_offset, first_old, first_new);
    printf("mutation_differences=%zu decoded_trits_equal=%d "
           "old_trits=%d,%d,%d,%d,%d new_trits=%d,%d,%d,%d,%d\n",
           mutation_differences, decoded_equal,
           old_trits[0], old_trits[1], old_trits[2], old_trits[3], old_trits[4],
           new_trits[0], new_trits[1], new_trits[2], new_trits[3], new_trits[4]);
    printf("negative_control_plus_one_verify_rc=%d\n", negative_control_rc);
    return accepted_mutations > 0 && mutation_differences == 1 &&
           decoded_equal == 1 && negative_control_rc != 0 ? 0 : 1;
}
