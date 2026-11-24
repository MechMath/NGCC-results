#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int print_limit_control(const char *name)
{
    struct rlimit limit;

    if (getrlimit(RLIMIT_AS, &limit) != 0) {
        perror("getrlimit");
        return -1;
    }
    printf("%s_soft_bytes=%llu\n", name,
           (unsigned long long)limit.rlim_cur);
    printf("%s_hard_bytes=%llu\n", name,
           (unsigned long long)limit.rlim_max);
    return 0;
}

int main(int argc, char **argv)
{
    const unsigned long long expected_len = sig_get_sn_len_bytes();
    unsigned long long message_len;
    unsigned long long sig_len = 0;
    unsigned char *message;
    unsigned char pk[6720];
    unsigned char sk[9920];
    unsigned char sig[12021];
    uint8_t seed[55];
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    int rc_keygen;
    int rc_sign;
    int rc_verify = -99;
    char *end = NULL;

    if (argc != 2) {
        fprintf(stderr, "usage: %s MESSAGE_BYTES\n", argv[0]);
        return 2;
    }
    errno = 0;
    message_len = strtoull(argv[1], &end, 10);
    if (errno || end == argv[1] || *end != '\0' || message_len == 0) {
        fprintf(stderr, "invalid message size\n");
        return 2;
    }
    if (message_len > SIZE_MAX) {
        fprintf(stderr, "message size does not fit size_t\n");
        return 2;
    }

    message = malloc((size_t)message_len);
    if (message == NULL) {
        fprintf(stderr, "caller message allocation failed before keygen\n");
        return 3;
    }
    memset(message, 0xA5, (size_t)message_len);

    for (size_t i = 0; i < sizeof(seed); ++i)
        seed[i] = (uint8_t)(0x5A ^ (uint8_t)i);
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "DRNG initialization failed\n");
        free(message);
        return 4;
    }

    if (print_limit_control("rlimit_as") != 0) {
        free(message);
        return 5;
    }
    printf("message_bytes=%llu\n", message_len);
    printf("expected_signature_bytes=%llu\n", expected_len);

    rc_keygen = sig_keygen(pk, &pk_len, sk, &sk_len);
    printf("keygen_lengths=%llu,%llu\n", pk_len, sk_len);
    printf("keygen_rc=%d\n", rc_keygen);
    if (rc_keygen != 0) {
        free(message);
        return 6;
    }

    rc_sign = sig_sign(sk, sig_get_sk_len_bytes(), message, message_len,
                       sig, &sig_len);
    printf("sign_rc=%d\n", rc_sign);
    printf("signature_len=%llu\n", sig_len);

    if (rc_sign == 0 && sig_len == expected_len) {
        rc_verify = sig_verify(pk, sig_get_pk_len_bytes(),
                               sig, sig_len, message, message_len);
    }
    printf("verify_rc=%d\n", rc_verify);
    printf("status_ambiguous=%d\n",
           rc_sign == 0 && sig_len == 0);

    free(message);
    return 0;
}
