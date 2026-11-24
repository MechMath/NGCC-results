#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "address.h"
#include "hash.h"
#include "params.h"
#include "thash.h"

static void fill(unsigned char *out, size_t len, unsigned char value)
{
    size_t i;
    for (i = 0; i < len; i++) {
        out[i] = (unsigned char)(value + (unsigned char)i);
    }
}

int main(void)
{
    unsigned char sk_seed[SPX_N];
    unsigned char pub_seed[SPX_N];
    unsigned char input[SPX_N];
    unsigned char a[SPX_N];
    unsigned char b[SPX_N];
    unsigned char c[SPX_N];
    uint32_t addr_a[8] = {0};
    uint32_t addr_b[8] = {0};
    uint32_t addr_c[8] = {0};
    uint32_t probes[] = {0, 1, 7, 127, 255, 256, 1023, 3583};
    size_t i;
    int failures = 0;

    fill(sk_seed, sizeof(sk_seed), 0x11);
    fill(pub_seed, sizeof(pub_seed), 0x22);
    fill(input, sizeof(input), 0x33);

    set_layer_addr(addr_a, 0);
    set_tree_addr(addr_a, UINT64_C(0x0123456789abcdef));
    set_keypair_addr(addr_a, 0x1234);
    memcpy(addr_b, addr_a, sizeof(addr_a));
    memcpy(addr_c, addr_a, sizeof(addr_a));

    set_type(addr_a, SPX_ADDR_TYPE_FORSPRF);
    set_type(addr_b, SPX_ADDR_TYPE_FORSPRF);
    set_type(addr_c, SPX_ADDR_TYPE_FORSPRF);

    for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        uint32_t x = probes[i];
        uint32_t y = x + 256;

        set_chain_addr(addr_a, x);
        set_hash_addr(addr_a, 0);
        set_chain_addr(addr_b, y);
        set_hash_addr(addr_b, 0);
        set_chain_addr(addr_c, x + 1);
        set_hash_addr(addr_c, 0);

        prf_addr(a, sk_seed, addr_a);
        prf_addr(b, sk_seed, addr_b);
        prf_addr(c, sk_seed, addr_c);

        printf("chain %u vs %u: PRF_equal=%d PRF_differs_from_x+1=%d\n",
               x, y, memcmp(a, b, SPX_N) == 0, memcmp(a, c, SPX_N) != 0);
        failures += memcmp(a, b, SPX_N) != 0;
        failures += memcmp(a, c, SPX_N) == 0;
    }

    set_type(addr_a, SPX_ADDR_TYPE_FORSCHAIN);
    set_type(addr_b, SPX_ADDR_TYPE_FORSCHAIN);
    set_type(addr_c, SPX_ADDR_TYPE_FORSCHAIN);

    for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        uint32_t x = probes[i];
        uint32_t y = x + 256;

        set_chain_addr(addr_a, x);
        set_hash_addr(addr_a, 1);
        set_chain_addr(addr_b, y);
        set_hash_addr(addr_b, 1);
        set_chain_addr(addr_c, x + 1);
        set_hash_addr(addr_c, 1);

        thash(a, input, 1, pub_seed, addr_a);
        thash(b, input, 1, pub_seed, addr_b);
        thash(c, input, 1, pub_seed, addr_c);

        printf("chain %u vs %u: FTS_CHAIN_equal=%d differs_from_x+1=%d\n",
               x, y, memcmp(a, b, SPX_N) == 0, memcmp(a, c, SPX_N) != 0);
        failures += memcmp(a, b, SPX_N) != 0;
        failures += memcmp(a, c, SPX_N) == 0;
    }

    printf("failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
