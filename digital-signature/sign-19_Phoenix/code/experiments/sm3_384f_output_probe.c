#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "hash.h"
#include "hash_sm3.h"
#include "params.h"
#include "thash.h"

static void hex(const unsigned char *x, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02x", x[i]);
    }
    putchar('\n');
}

int main(void)
{
    spx_ctx ctx;
    uint32_t addr[8] = {0};
    unsigned char out[2 * SPX_N];
    unsigned char thash_out[2 * SPX_N];
    unsigned char thash_in[2 * SPX_N];
    unsigned char thash_buf[SPX_SM3_ADDR_BYTES + sizeof(thash_in)];
    unsigned char expected[SPX_SM3_OUTPUT_BYTES];
    unsigned char thash_expected[SPX_SM3_OUTPUT_BYTES];
    unsigned char seeded[40];
    unsigned char block[SPX_SM3_BLOCK_BYTES] = {0};
    unsigned char buf[SPX_SM3_ADDR_BYTES + SPX_N];

    for (size_t i = 0; i < SPX_N; i++) {
        ctx.pub_seed[i] = (unsigned char)(0x10 + i);
        ctx.sk_seed[i] = (unsigned char)(0x80 + i);
    }
    for (size_t i = 0; i < SPX_ADDR_BYTES; i++) {
        ((unsigned char *)addr)[i] = (unsigned char)(0x40 + i);
    }
    for (size_t i = 0; i < sizeof(thash_in); i++) {
        thash_in[i] = (unsigned char)(0xc0 + i);
    }
    initialize_hash_function(&ctx);

    memset(out, 0xa5, sizeof(out));
    prf_addr(out, &ctx, addr);

    memcpy(block, ctx.pub_seed, SPX_N);
    sm3_inc_init(seeded);
    sm3_inc_blocks(seeded, block, 1);
    memcpy(buf, addr, SPX_SM3_ADDR_BYTES);
    memcpy(buf + SPX_SM3_ADDR_BYTES, ctx.sk_seed, SPX_N);
    sm3_inc_finalize(expected, seeded, buf, sizeof(buf));

    printf("expected_32=");
    hex(expected, sizeof(expected));
    printf("prf_first_32=");
    hex(out, 32);
    printf("prf_suffix_%d=", SPX_N - 32);
    hex(out + 32, SPX_N - 32);
    printf("first32_match=%d suffix_equals_prefix=%d\n",
           memcmp(expected, out, 32) == 0,
           memcmp(out + 32, out, SPX_N - 32) == 0);

    memset(thash_out, 0xa5, sizeof(thash_out));
    thash(thash_out, thash_in, 2, &ctx, addr);

    memcpy(block, ctx.pub_seed, SPX_N);
    sm3_inc_init(seeded);
    sm3_inc_blocks(seeded, block, 1);
    memcpy(thash_buf, addr, SPX_SM3_ADDR_BYTES);
    memcpy(thash_buf + SPX_SM3_ADDR_BYTES, thash_in, sizeof(thash_in));
    sm3_inc_finalize(thash_expected, seeded, thash_buf, sizeof(thash_buf));

    printf("thash_expected_32=");
    hex(thash_expected, sizeof(thash_expected));
    printf("thash_first_32=");
    hex(thash_out, 32);
    printf("thash_suffix_%d=", SPX_N - 32);
    hex(thash_out + 32, SPX_N - 32);
    printf("thash_first32_match=%d thash_suffix_equals_prefix=%d\n",
           memcmp(thash_expected, thash_out, 32) == 0,
           memcmp(thash_out + 32, thash_out, SPX_N - 32) == 0);
    return 0;
}
