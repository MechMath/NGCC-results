#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "api.h"
#include "params.h"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "utils.h"
#include "hash.h"
#include "address.h"
#include "pors_precomputed.h"

DRNG_ctx drng_algorithm;

int pors_message_to_indices(uint32_t *indices, const unsigned char *R,
                            const unsigned char *m, uint32_t ctr);

static size_t append_unique_u32(uint32_t *out, size_t out_len, uint32_t value)
{
    if (out_len == 0 || out[out_len - 1] != value) out[out_len++] = value;
    return out_len;
}

static size_t merge_sorted_u32(uint32_t *dst, const uint32_t *left,
                               size_t left_len, const uint32_t *right,
                               size_t right_len)
{
    size_t i = 0;
    size_t j = 0;
    size_t out_len = 0;
    while (i < left_len || j < right_len) {
        uint32_t value;
        if (j >= right_len || (i < left_len && left[i] < right[j])) {
            value = left[i++];
        } else if (i >= left_len || right[j] < left[i]) {
            value = right[j++];
        } else {
            value = left[i++];
            j++;
        }
        if (out_len == 0 || dst[out_len - 1] != value) dst[out_len++] = value;
    }
    return out_len;
}

static size_t octopus_auth_count(const uint32_t *indices)
{
    uint32_t current[SPX_PORS_FP_K];
    uint32_t upper[SPX_PORS_FP_K];
    uint32_t parents[SPX_PORS_FP_K];
    uint32_t merged[SPX_PORS_FP_K];
    size_t current_len = 0;
    size_t upper_len = 0;
    size_t auth_len = 0;

    for (size_t i = 0; i < SPX_PORS_FP_K; i++) {
        if (indices[i] < 2u * PORS_SHORT_LEAF_START_CONST) {
            current[current_len++] = indices[i];
        } else {
            upper[upper_len++] = PORS_SHORT_LEAF_START_CONST +
                                 (indices[i] - 2u * PORS_SHORT_LEAF_START_CONST);
        }
    }

    for (uint32_t level = PORS_TREE_HEIGHT_CONST; level > 0; level--) {
        size_t parent_len = 0;
        size_t j = 0;
        while (j < current_len) {
            const uint32_t node = current[j];
            parents[parent_len] = node >> 1;
            parent_len = append_unique_u32(parents, parent_len, node >> 1);
            if (j + 1 < current_len && current[j + 1] == (node ^ 1u)) {
                j += 2;
            } else {
                auth_len++;
                j++;
            }
        }
        current_len = merge_sorted_u32(merged, parents, parent_len,
                                       upper, upper_len);
        memcpy(current, merged, current_len * sizeof(uint32_t));
        upper_len = 0;
    }
    return auth_len;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int read_hex_line(FILE *f, const char *name, unsigned char *out,
                         size_t expected_len)
{
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    int ok = 0;

    while ((got = getline(&line, &cap, f)) >= 0) {
        const size_t name_len = strlen(name);
        if (got > (ssize_t)name_len && memcmp(line, name, name_len) == 0) {
            const char *hex = line + name_len;
            const size_t hex_len = strlen(hex);
            if (hex_len < 2 || hex[hex_len - 1] != '\n' ||
                hex_len - 1 != expected_len * 2) {
                break;
            }
            for (size_t i = 0; i < expected_len; i++) {
                const int hi = hex_nibble(hex[2 * i]);
                const int lo = hex_nibble(hex[2 * i + 1]);
                if (hi < 0 || lo < 0) goto done;
                out[i] = (unsigned char)((hi << 4) | lo);
            }
            ok = 1;
            break;
        }
    }

done:
    free(line);
    return ok;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: %s KAT_FILE VECTOR_INDEX [PARAMETER_NAME]\n", argv[0]);
        return 2;
    }

    FILE *f = fopen(argv[1], "r");
    if (f == NULL) return 3;

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sig[CRYPTO_BYTES];
    const int wanted_vector = atoi(argv[2]);
    const char *parameter_name = argc == 4 ? argv[3] : CRYPTO_ALGNAME;

    int m_len = 0;
    char *line = NULL;
    size_t cap = 0;
    ssize_t got;
    int found_vector = 0;
    while ((got = getline(&line, &cap, f)) >= 0) {
        if (got > 8 && memcmp(line, "Count = ", 8) == 0) {
            const int vector_index = atoi(line + 8);
            if (vector_index == wanted_vector) {
                found_vector = 1;
            } else if (found_vector) {
                break;
            }
        } else if (found_vector && got > 8 && memcmp(line, "M_Len = ", 8) == 0) {
            m_len = atoi(line + 8);
        }
    }
    free(line);
    line = NULL;
    cap = 0;

    if (!found_vector || m_len <= 0 || m_len > 65536) {
        fclose(f);
        return 4;
    }
    unsigned char *msg = malloc((size_t)m_len);
    if (msg == NULL) {
        fclose(f);
        return 5;
    }

    rewind(f);
    const char count_prefix[32] = {0};
    snprintf((char *)count_prefix, sizeof(count_prefix), "Count = %d\n",
             wanted_vector);
    found_vector = 0;
    while ((got = getline(&line, &cap, f)) >= 0) {
        if (got > 0 && strcmp(line, count_prefix) == 0) {
            found_vector = 1;
            break;
        }
    }
    if (!found_vector ||
        !read_hex_line(f, "PK = ", pk, sizeof(pk)) ||
        !read_hex_line(f, "M = ", msg, (size_t)m_len) ||
        !read_hex_line(f, "Sn = ", sig, sizeof(sig))) {
        fclose(f);
        free(msg);
        return 6;
    }
    fclose(f);

    const int before = sig_verify(pk, sizeof(pk), sig, sizeof(sig),
                                  msg, (unsigned long long)m_len);

    const size_t pors_auth_start =
        (size_t)SPX_N + COUNTER_SIZE +
        (size_t)SPX_PORS_FP_K * SPX_N;
    const size_t pors_auth_end =
        (size_t)SPX_N + SPX_PORS_FP_BYTES;

    spx_ctx ctx = {0};
    unsigned char mhash[SPX_PORS_FP_MSG_BYTES];
    uint64_t tree = 0;
    uint32_t leaf_idx = 0;
    uint32_t indices[SPX_PORS_FP_K];
    const uint32_t ctr = (uint32_t)bytes_to_ull(sig + SPX_N, COUNTER_SIZE);
    memcpy(ctx.pub_seed, pk, SPX_N);
    if (hash_message(mhash, &tree, &leaf_idx, sig, pk, msg,
                     (unsigned long long)m_len, &ctx) != 0 ||
        pors_message_to_indices(indices, sig, mhash, ctr) != 0) {
        fprintf(stderr, "failed to derive PORS indices\n");
        free(msg);
        return 7;
    }
    const size_t auth_nodes = octopus_auth_count(indices);
    const size_t padding_nodes = SPX_PORS_FP_MAX_AUTH_NODES - auth_nodes;
    if (auth_nodes > SPX_PORS_FP_MAX_AUTH_NODES || padding_nodes == 0) {
        fprintf(stderr, "vector has no padding: auth_nodes=%zu maximum=%u\n",
                auth_nodes, (unsigned int)SPX_PORS_FP_MAX_AUTH_NODES);
        free(msg);
        return 8;
    }

    const size_t mutation_offset =
        pors_auth_start + auth_nodes * SPX_N;
    const unsigned char old_value = sig[mutation_offset];
    sig[mutation_offset] = 0xA5;

    const int after = sig_verify(pk, sizeof(pk), sig, sizeof(sig),
                                 msg, (unsigned long long)m_len);

    printf("parameter=%s\n", parameter_name);
    printf("vector=%d\n", wanted_vector);
    printf("signature_bytes=%u\n", (unsigned int)sizeof(sig));
    printf("pors_auth_start=%zu\n", pors_auth_start);
    printf("pors_auth_end=%zu\n", pors_auth_end);
    printf("pors_auth_nodes=%zu\n", auth_nodes);
    printf("pors_padding_nodes=%zu\n", padding_nodes);
    printf("pors_padding_bytes=%zu\n", padding_nodes * SPX_N);
    printf("mutation_offset=%zu\n", mutation_offset);
    printf("mutation_old=0x%02X mutation_new=0x%02X\n",
           old_value, sig[mutation_offset]);
    printf("verify_before=%d\n", before);
    printf("verify_after_noncanonical_padding_mutation=%d\n", after);

    free(msg);
    return (before == 0 && after == 0) ? 0 : 1;
}
