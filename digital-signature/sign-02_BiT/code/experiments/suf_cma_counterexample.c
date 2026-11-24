#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int write_file(const char *path, const unsigned char *data, size_t len) {
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

int main(int argc, char **argv) {
    const char *outdir = (argc > 1) ? argv[1] : ".";
    char path[512];
    unsigned char seed[55];
    const unsigned char msg[] =
        "BiT SUF-CMA same-message experiment: this message is queried twice.";
    unsigned char pk[16384];
    unsigned char sk[16384];
    unsigned char sig1[16384];
    unsigned char sig2[16384];
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long sig1_len = 0;
    unsigned long long sig2_len = 0;
    size_t differing_bytes = 0;
    int first_difference = -1;

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0xA5U + 17U * 2026U + 31U * 11U + i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "ERROR: DRNG initialization failed\n");
        return 2;
    }
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
        fprintf(stderr, "ERROR: key generation failed\n");
        return 3;
    }
    if (sig_sign(sk, sk_len, (unsigned char *)msg, sizeof(msg) - 1,
                 sig1, &sig1_len) != 0) {
        fprintf(stderr, "ERROR: first signing query failed\n");
        return 4;
    }
    if (sig_sign(sk, sk_len, (unsigned char *)msg, sizeof(msg) - 1,
                 sig2, &sig2_len) != 0) {
        fprintf(stderr, "ERROR: second signing query failed\n");
        return 5;
    }

    if (sig1_len != sig2_len) {
        fprintf(stderr, "ERROR: signature lengths differ\n");
        return 6;
    }
    for (size_t i = 0; i < sig1_len; i++) {
        if (sig1[i] != sig2[i]) {
            if (first_difference < 0) {
                first_difference = (int)i;
            }
            differing_bytes++;
        }
    }

    int verify1 = sig_verify(pk, pk_len, sig1, sig1_len,
                             (unsigned char *)msg, sizeof(msg) - 1);
    int verify2 = sig_verify(pk, pk_len, sig2, sig2_len,
                             (unsigned char *)msg, sizeof(msg) - 1);

    snprintf(path, sizeof(path), "%s/pk.bin", outdir);
    if (write_file(path, pk, (size_t)pk_len) != 0) return 7;
    snprintf(path, sizeof(path), "%s/message.bin", outdir);
    if (write_file(path, msg, sizeof(msg) - 1) != 0) return 8;
    snprintf(path, sizeof(path), "%s/sig1.bin", outdir);
    if (write_file(path, sig1, (size_t)sig1_len) != 0) return 9;
    snprintf(path, sizeof(path), "%s/sig2.bin", outdir);
    if (write_file(path, sig2, (size_t)sig2_len) != 0) return 10;

    printf("algorithm=%s\n", ALGORITHM_INSTANCE);
    printf("pk_len=%llu sk_len=%llu sig_len=%llu\n",
           pk_len, sk_len, sig1_len);
    printf("same_message=1 same_public_key=1\n");
    printf("signatures_equal=%d differing_bytes=%zu first_difference=%d\n",
           memcmp(sig1, sig2, (size_t)sig1_len) == 0,
           differing_bytes, first_difference);
    printf("verify_sig1=%d verify_sig2=%d\n", verify1, verify2);
    return (verify1 == 0 && verify2 == 0 &&
            memcmp(sig1, sig2, (size_t)sig1_len) != 0) ? 0 : 1;
}
