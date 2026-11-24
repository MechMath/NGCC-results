#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"
#include "hash.h"
#include "params.h"
#include "utils.h"

#define ZERO_BYTES ((SPX_FORS_ZERO_LAST_BITS + 7) / 8)
#define TREE_BITS (SPX_FULL_HEIGHT - SPX_TREE_HEIGHT + 1)
#define TREE_BYTES ((TREE_BITS + 7) / 8)
#define LEAF_BITS SPX_BOTTOM_TREE_HEIGHT
#define LEAF_BYTES ((LEAF_BITS + 7) / 8)
#define DGST_BYTES (ZERO_BYTES + SPX_FORS_MSG_BYTES + TREE_BYTES + LEAF_BYTES)

void hash_with_counter(unsigned char *buf_out, const unsigned char *R,
                       const unsigned char *pk, const unsigned char *m,
                       unsigned long long mlen, unsigned char *counter_bytes);

static unsigned char deterministic_byte(unsigned int domain,
                                        unsigned int sample,
                                        unsigned int index)
{
    uint32_t x = 0x9e3779b9u ^ (domain * 0x85ebca6bu) ^
                 (sample * 0xc2b2ae35u) ^ index;
    x ^= x >> 16;
    x *= 0x7feb352du;
    x ^= x >> 15;
    x *= 0x846ca68bu;
    x ^= x >> 16;
    return (unsigned char)x;
}

int main(void)
{
    unsigned char R[SPX_N];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char m[32];
    unsigned char digest[DGST_BYTES];
    unsigned char counter_bytes[COUNTER_SIZE];
    unsigned int accepted = 0;
    unsigned int nonzero_tree = 0;
    unsigned int checked = 0;
    spx_ctx ctx;

    memset(&ctx, 0, sizeof(ctx));

    for (unsigned int sample = 0; sample < 32; sample++) {
        for (unsigned int i = 0; i < SPX_N; i++) {
            R[i] = deterministic_byte(1, sample, i);
            m[i % sizeof(m)] = deterministic_byte(2, sample, i);
        }
        for (unsigned int i = 0; i < SPX_PK_BYTES; i++) {
            pk[i] = deterministic_byte(3, sample, i);
        }

        for (uint32_t counter = 1; counter < (1u << 20); counter++) {
            ull_to_bytes(counter_bytes, COUNTER_SIZE, counter);
            hash_with_counter(digest, R, pk, m, sizeof(m), counter_bytes);
            checked++;

            uint64_t zero = bytes_to_ull(digest, ZERO_BYTES);
            if ((zero & ((1ull << SPX_FORS_ZERO_LAST_BITS) - 1)) != 0) {
                continue;
            }

            const unsigned char *tree_bytes =
                digest + ZERO_BYTES + SPX_FORS_MSG_BYTES;
            uint64_t parsed_tree = bytes_to_ull(tree_bytes, TREE_BYTES);
            uint32_t reported_leaf = 0;
            uint32_t reported_counter = counter;
            unsigned char reported_digest[SPX_FORS_MSG_BYTES];
            int rc = hash_message(reported_digest, &parsed_tree, &reported_leaf,
                                  R, pk, m, sizeof(m), &ctx,
                                  &reported_counter);
            if (rc != 0) {
                fprintf(stderr, "hash_message rejected an accepted counter\n");
                return 1;
            }

            uint64_t true_tree = bytes_to_ull(tree_bytes, TREE_BYTES);
            if (memcmp(reported_digest, digest + ZERO_BYTES,
                       SPX_FORS_MSG_BYTES) != 0) {
                fprintf(stderr, "digest bytes mismatch\n");
                return 1;
            }

            printf("sample=%u counter=%u parsed_tree=%llu reported_tree=%llu "
                   "leaf=%u\n",
                   sample, counter, (unsigned long long)true_tree,
                   (unsigned long long)parsed_tree, reported_leaf);
            accepted++;
            if (true_tree != 0) {
                nonzero_tree++;
            }
            break;
        }
    }

    printf("summary checked=%u accepted=%u parsed_tree_nonzero=%u\n",
           checked, accepted, nonzero_tree);
    return (accepted == 32 && nonzero_tree > 0) ? 0 : 2;
}
