#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "octopus.h"
#include "params.h"
#include "tfors.h"

static uint64_t state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t next_u64(void) {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * UINT64_C(0x2545f4914f6cdd1d);
}

int main(int argc, char **argv) {
    unsigned long trials = argc > 1 ? strtoul(argv[1], NULL, 10) : 100000;
    unsigned char digest[SPX_TFORS_MSG_BYTES];
    uint32_t indices[SPX_TFORS_K];
    uint32_t auth_count;
    spx_ctx ctx;
    unsigned long at_ref_max = 0;
    unsigned long at_opt_only = 0;
    unsigned long accepted_ref = 0;
    unsigned long accepted_opt = 0;
    const unsigned long ref_auth_max =
        (SPX_TFORS_SIG_MAX - (unsigned long)SPX_TFORS_K * SPX_N) / SPX_N;
    const unsigned long opt_auth_max = ref_auth_max + 1;

    memset(&ctx, 0, sizeof(ctx));
    for (size_t i = 0; i < sizeof(ctx.pub_seed); i++) {
        ctx.pub_seed[i] = (unsigned char)(0xa5U ^ (unsigned char)i);
    }

    for (unsigned long t = 0; t < trials; t++) {
        for (size_t i = 0; i < sizeof(digest); i += 8) {
            uint64_t x = next_u64();
            size_t take = sizeof(digest) - i;
            if (take > 8) {
                take = 8;
            }
            memcpy(digest + i, &x, take);
        }

        message_to_indices(indices, digest, &ctx);
        octopus_compute_auth_count(indices, SPX_TFORS_K, &auth_count);

        if (auth_count <= ref_auth_max) {
            accepted_ref++;
            if (auth_count == ref_auth_max) {
                at_ref_max++;
            }
        }
        if (auth_count <= opt_auth_max) {
            accepted_opt++;
            if (auth_count == opt_auth_max) {
                at_opt_only++;
            }
        }
    }

    printf("trials=%lu ref_auth_max=%lu opt_auth_max=%lu "
           "accepted_ref=%lu accepted_opt=%lu at_ref_max=%lu "
           "opt_only=%lu\n",
           trials, ref_auth_max, opt_auth_max, accepted_ref, accepted_opt,
           at_ref_max, at_opt_only);
    return 0;
}
