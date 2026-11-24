#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

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
    unsigned int seed_domain = (argc > 2) ? (unsigned int)strtoul(argv[2], NULL, 0) : 2026U;
    unsigned int rounds = (argc > 3) ? (unsigned int)strtoul(argv[3], NULL, 0) : 32U;
    unsigned char seed[55];
    unsigned char pk[16384];
    unsigned char sk[16384];
    unsigned char sig[16384];
    unsigned char *invalid_sig = NULL;
    unsigned long long pk_len = 0;
    unsigned long long sk_len = 0;
    unsigned long long invalid_sig_len = 0;
    unsigned char msg[96];
    unsigned int sign_failures = 0;
    unsigned int verify_failures = 0;
    unsigned int unique_successful_signatures = 0;
    unsigned char previous[16384];
    unsigned long long previous_len = 0;

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0xA5U + 17U * seed_domain + 31U * 11U + i);
    }
    for (size_t i = 0; i < sizeof(msg); i++) {
        msg[i] = (unsigned char)((i * 37U + seed_domain) & 0xFFU);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
    if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 3;

    printf("algorithm=%s seed_domain=%u rounds=%u\n",
           ALGORITHM_INSTANCE, seed_domain, rounds);
    printf("pk_len=%llu sk_len=%llu\n", pk_len, sk_len);
    for (unsigned int i = 0; i < rounds; i++) {
        unsigned long long sig_len = 0;
        int sign_rc = sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len);
        int verify_rc = (sign_rc == 0)
            ? sig_verify(pk, pk_len, sig, sig_len, msg, sizeof(msg))
            : -999;
        int changed = (i == 0 || previous_len != sig_len ||
                       memcmp(previous, sig, (size_t)sig_len) != 0);
        if (sign_rc != 0) sign_failures++;
        if (sign_rc == 0 && verify_rc != 0) {
            verify_failures++;
            if (invalid_sig == NULL) {
                invalid_sig = malloc((size_t)sig_len);
                if (invalid_sig != NULL) {
                    memcpy(invalid_sig, sig, (size_t)sig_len);
                    invalid_sig_len = sig_len;
                }
            }
        }
        if (sign_rc == 0 && changed) unique_successful_signatures++;
        printf("round=%u sign_rc=%d verify_rc=%d sig_len=%llu changed=%d\n",
               i, sign_rc, verify_rc, sig_len, changed);
        if (sign_rc == 0) {
            memcpy(previous, sig, (size_t)sig_len);
            previous_len = sig_len;
        }
    }
    printf("sign_failures=%u verify_failures=%u unique_successful_signatures=%u\n",
           sign_failures, verify_failures, unique_successful_signatures);

    if (invalid_sig != NULL) {
        char path[512];
        snprintf(path, sizeof(path), "%s/pk.bin", outdir);
        if (write_file(path, pk, (size_t)pk_len) != 0) return 4;
        snprintf(path, sizeof(path), "%s/message.bin", outdir);
        if (write_file(path, msg, sizeof(msg)) != 0) return 5;
        snprintf(path, sizeof(path), "%s/invalid_sig.bin", outdir);
        if (write_file(path, invalid_sig, (size_t)invalid_sig_len) != 0) return 6;
    }
    free(invalid_sig);
    return verify_failures == 0 ? 0 : 1;
}
