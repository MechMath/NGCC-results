#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "context.h"
#include "params.h"

extern int __real_SPX_h2_generate_indices(uint32_t *indices,
                                          const unsigned char *msg_digest,
                                          const spx_ctx *ctx);

static char current_phase = '?';
static unsigned long phase_calls;
static unsigned long phase_failures;
static int last_failure;

int __wrap_SPX_h2_generate_indices(uint32_t *indices,
                                   const unsigned char *msg_digest,
                                   const spx_ctx *ctx) {
    int rc = __real_SPX_h2_generate_indices(indices, msg_digest, ctx);
    phase_calls++;
    last_failure = rc != 0;
    if (rc != 0) {
        phase_failures++;
    }
    return rc;
}

int main(int argc, char **argv) {
    const unsigned long trials = argc > 1 ? strtoul(argv[1], NULL, 10) : 40;
    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char sk[SPX_SK_BYTES];
    unsigned char msg[32];
    unsigned char sig[SPX_BYTES];
    unsigned long sign_fail = 0;
    unsigned long verify_fail = 0;
    unsigned long sign_h2_fail_trials = 0;
    unsigned long verify_h2_fail_trials = 0;
    unsigned long any_h2_fail_trials = 0;
    unsigned long sign_final_h2_fail_trials = 0;
    unsigned long verify_h2_fail_on_final_sign_failure = 0;

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0x5aU ^ (unsigned char)i);
    }

    if (crypto_sign_seed_keypair(pk, sk, seed) != 0) {
        puts("keypair generation failed");
        return 2;
    }

    for (unsigned long t = 0; t < trials; t++) {
        size_t siglen = 0;
        size_t tfors_len = 0;
        unsigned long sign_calls;
        unsigned long sign_fails;
        int sign_final_failure;
        unsigned long verify_calls;
        unsigned long verify_fails;

        memset(msg, 0, sizeof(msg));
        msg[0] = (unsigned char)t;
        msg[1] = (unsigned char)(t >> 8);
        msg[2] = (unsigned char)(t >> 16);
        msg[3] = (unsigned char)(t >> 24);

        current_phase = 'S';
        phase_calls = 0;
        phase_failures = 0;
        last_failure = 0;
        int sr = crypto_sign_signature(sig, &siglen, &tfors_len,
                                       msg, sizeof(msg), sk);
        sign_calls = phase_calls;
        sign_fails = phase_failures;
        sign_final_failure = last_failure;

        if (sr != 0) {
            sign_fail++;
            printf("trial=%lu sign_fail=%d sign_calls=%lu sign_h2_fail=%lu\n",
                   t, sr, sign_calls, sign_fails);
            continue;
        }

        current_phase = 'V';
        phase_calls = 0;
        phase_failures = 0;
        last_failure = 0;
        int vr = crypto_sign_verify(sig, siglen, msg, sizeof(msg), pk);
        verify_calls = phase_calls;
        verify_fails = phase_failures;

        if (vr != 0) {
            verify_fail++;
        }
        if (sign_fails != 0) {
            sign_h2_fail_trials++;
        }
        if (sign_final_failure) {
            sign_final_h2_fail_trials++;
        }
        if (verify_fails != 0) {
            verify_h2_fail_trials++;
        }
        if (sign_fails != 0 || verify_fails != 0) {
            any_h2_fail_trials++;
            printf("trial=%lu sign_calls=%lu sign_h2_fail=%lu verify_rc=%d "
                   "verify_calls=%lu verify_h2_fail=%lu siglen=%zu tfors_len=%zu\n",
                   t, sign_calls, sign_fails, vr, verify_calls, verify_fails,
                   siglen, tfors_len);
        }
        if (sign_final_failure) {
            printf("final_failure trial=%lu verify_rc=%d verify_h2_fail=%lu "
                   "siglen=%zu tfors_len=%zu\n",
                   t, vr, verify_fails, siglen, tfors_len);
            if (verify_fails != 0) {
                verify_h2_fail_on_final_sign_failure++;
            }
        }
    }

    printf("SUMMARY trials=%lu sign_fail=%lu verify_fail_after_sign_ok=%lu "
           "sign_h2_fail_trials=%lu verify_h2_fail_trials=%lu "
           "any_h2_fail_trials=%lu sign_final_h2_fail_trials=%lu "
           "verify_h2_fail_on_final_sign_failure=%lu\n",
           trials, sign_fail, verify_fail, sign_h2_fail_trials,
           verify_h2_fail_trials, any_h2_fail_trials,
           sign_final_h2_fail_trials,
           verify_h2_fail_on_final_sign_failure);
    return verify_fail == 0 ? 0 : 1;
}
