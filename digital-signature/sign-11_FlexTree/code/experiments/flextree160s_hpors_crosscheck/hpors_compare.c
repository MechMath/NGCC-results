#define static
#include "pors_fp.c"
#undef static
#include <stdio.h>

static void spec_hpors_mod(pors_u256 *value, const unsigned char *R,
                           const unsigned char *m, uint32_t ctr)
{
    unsigned char inner_input[2 * SPX_N + (64 - 2 * SPX_N) + COUNTER_SIZE];
    unsigned char digest[32];
    unsigned char hpors[PORS_HPORS_INPUT_BYTES];
    unsigned char ctr_bytes[COUNTER_SIZE];
    size_t off = 0;

    memset(inner_input, 0, sizeof(inner_input));
    memcpy(inner_input + off, R, SPX_N); off += SPX_N;
    memcpy(inner_input + off, m, SPX_PORS_FP_MSG_BYTES);
    off += SPX_PORS_FP_MSG_BYTES;
    off += 64 - 2 * SPX_N;
    ull_to_bytes(ctr_bytes, COUNTER_SIZE, ctr);
    memcpy(inner_input + off, ctr_bytes, COUNTER_SIZE);
    sm3hash(256, inner_input, sizeof(inner_input) * 8, digest);
    pseudoXOF(sizeof(hpors) * 8, digest, sizeof(digest) * 8, hpors);
    pors_hpors_reduce_bytes(value, hpors);
}

static uint32_t next_u32(uint32_t *s)
{
    *s = *s * 1664525u + 1013904223u;
    return *s;
}

int main(void)
{
    unsigned char R[SPX_N], m[SPX_PORS_FP_MSG_BYTES];
    uint32_t state = 1;
    unsigned int different = 0;
    unsigned int indices_different = 0;
    const unsigned int trials = 1000;

    for (unsigned int t = 0; t < trials; t++) {
        pors_u256 impl, spec;
        for (size_t i = 0; i < sizeof(R); i++) R[i] = (unsigned char)next_u32(&state);
        for (size_t i = 0; i < sizeof(m); i++) m[i] = (unsigned char)next_u32(&state);
        pors_hpors_mod(&impl, R, m, t);
        spec_hpors_mod(&spec, R, m, t);
        if (pors_u256_cmp(&impl, &spec) != 0) different++;
        {
            uint32_t impl_indices[SPX_PORS_FP_K];
            uint32_t spec_indices[SPX_PORS_FP_K];
            if (pors_decode_combination(impl_indices, &impl) != 0 ||
                pors_decode_combination(spec_indices, &spec) != 0) {
                puts("DECODE_FAIL");
                return 2;
            }
            if (memcmp(impl_indices, spec_indices, sizeof(impl_indices)) != 0)
                indices_different++;
        }
        if (t == 0) {
            printf("TRIAL0_IMPL=");
            for (int i = 2; i >= 0; i--) printf("%016llx", (unsigned long long)impl.limb[i]);
            printf("\nTRIAL0_SPEC=");
            for (int i = 2; i >= 0; i--) printf("%016llx", (unsigned long long)spec.limb[i]);
            puts("");
        }
    }
    printf("HPORS_VALUE_DIFFERENT=%u/%u\n", different, trials);
    printf("PORS_INDICES_DIFFERENT=%u/%u\n", indices_different, trials);
    {
        FILE *f = fopen("kat_first.bin", "rb");
        unsigned char pk[SPX_PK_BYTES], kat_m[56], kat_R[SPX_N], ctr_bytes[COUNTER_SIZE];
        unsigned char md[SPX_PORS_FP_MSG_BYTES];
        uint32_t ctr, kat_leaf;
        uint64_t kat_tree;
        pors_u256 impl, spec;
        uint32_t impl_indices[SPX_PORS_FP_K], spec_indices[SPX_PORS_FP_K];
        spx_ctx ctx = {0};
        if (f == NULL ||
            fread(pk, 1, sizeof(pk), f) != sizeof(pk) ||
            fread(kat_m, 1, sizeof(kat_m), f) != sizeof(kat_m) ||
            fread(kat_R, 1, sizeof(kat_R), f) != sizeof(kat_R) ||
            fread(ctr_bytes, 1, sizeof(ctr_bytes), f) != sizeof(ctr_bytes)) {
            puts("KAT_READ_FAIL");
            return 2;
        }
        fclose(f);
        memcpy(ctx.pub_seed, pk, SPX_N);
        initialize_hash_function(&ctx);
        hash_message(md, &kat_tree, &kat_leaf, kat_R, pk, kat_m, sizeof(kat_m), &ctx);
        ctr = (uint32_t)bytes_to_ull(ctr_bytes, COUNTER_SIZE);
        pors_hpors_mod(&impl, kat_R, md, ctr);
        spec_hpors_mod(&spec, kat_R, md, ctr);
        if (pors_decode_combination(impl_indices, &impl) != 0 ||
            pors_decode_combination(spec_indices, &spec) != 0) {
            puts("KAT_DECODE_FAIL");
            return 2;
        }
        printf("KAT0_CTR=%u TREE=%llu LEAF=%u IMPL_EQ_SPEC=%d INDICES_EQ_SPEC=%d\n",
               ctr, (unsigned long long)kat_tree, kat_leaf,
               pors_u256_cmp(&impl, &spec) == 0,
               memcmp(impl_indices, spec_indices, sizeof(impl_indices)) == 0);
    }
    return indices_different == trials ? 0 : 1;
}
