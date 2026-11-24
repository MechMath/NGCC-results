#include <stdint.h>
#include <stdio.h>
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

int main(void)
{
    unsigned char R[SPX_N];
    unsigned char pk[SPX_PK_BYTES];
    unsigned char m[32];
    unsigned char digest[DGST_BYTES];
    unsigned char md[SPX_FORS_MSG_BYTES];
    unsigned char counter_bytes[COUNTER_SIZE];
    unsigned int histogram[256] = {0};
    unsigned int reported_histogram[256] = {0};
    spx_ctx ctx = {0};

    for (unsigned int i = 0; i < SPX_N; i++) {
        R[i] = (unsigned char)(0x40 + i);
    }
    for (unsigned int i = 0; i < SPX_PK_BYTES; i++) {
        pk[i] = (unsigned char)(0x80 + i);
    }
    for (unsigned int i = 0; i < sizeof(m); i++) {
        m[i] = (unsigned char)(0xc0 + i);
    }

    unsigned int accepted = 0;
    for (uint32_t counter = 1; counter < (1u << 20); counter++) {
        ull_to_bytes(counter_bytes, COUNTER_SIZE, counter);
        hash_with_counter(digest, R, pk, m, sizeof(m), counter_bytes);
        uint64_t zero = bytes_to_ull(digest, ZERO_BYTES);
        if ((zero & ((1ull << SPX_FORS_ZERO_LAST_BITS) - 1)) != 0) {
            continue;
        }
        uint32_t reported_counter = counter;
        uint32_t leaf = UINT32_MAX;
        uint64_t tree = ~(uint64_t)0;
        if (hash_message(md, &tree, &leaf, R, pk, m, sizeof(m),
                         &ctx, &reported_counter) != 0) {
            return 2;
        }
        const unsigned char *leaf_bytes =
            digest + ZERO_BYTES + SPX_FORS_MSG_BYTES + TREE_BYTES;
        unsigned int raw_leaf = leaf_bytes[0];
        histogram[raw_leaf]++;
        if (leaf < 256) {
            reported_histogram[leaf]++;
        }
        accepted++;
        if (accepted <= 16) {
            printf("counter=%u raw_leaf=%u raw_leaf_bytes=%u reported_leaf=%u\n",
                   counter, raw_leaf, LEAF_BYTES, leaf);
        }
    }

    unsigned int raw_support = 0;
    unsigned int reported_support = 0;
    for (unsigned int i = 0; i < 256; i++) {
        if (histogram[i]) {
            raw_support++;
        }
    }
    for (unsigned int i = 0; i < 256; i++) {
        if (reported_histogram[i]) {
            reported_support++;
        }
    }
    printf("accepted=%u raw_support=%u reported_support_upper=%u "
           "raw_min_nonzero=", accepted, raw_support, reported_support);
    for (unsigned int i = 0; i < 256; i++) {
        if (histogram[i]) {
            printf("%u", i);
            break;
        }
    }
    printf(" raw_max_nonzero=");
    for (unsigned int i = 255; ; i--) {
        if (histogram[i]) {
            printf("%u", i);
            break;
        }
        if (i == 0) {
            break;
        }
    }
    printf("\n");
    return 0;
}
