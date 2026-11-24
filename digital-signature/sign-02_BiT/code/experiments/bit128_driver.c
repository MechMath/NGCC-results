#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "drng.h"
#include "packing.h"
#include "params.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"

#ifndef DRIVER_LABEL
#define DRIVER_LABEL "unknown"
#endif

#define TUPLE_MAGIC "BIT128PK1"
#define TUPLE_MAGIC_LEN 9
#define D 1681ULL
#define D2 (D * D)
#define D3 (D * D * D)
#define D4 (D * D * D * D)
#define MASK43 ((1ULL << 43) - 1)
#define TR_OFFSET (BIT_SEEDBYTES + BIT_POLYVECK_B1_BYTES + BIT_SEEDBYTES)

DRNG_ctx drng_algorithm;

typedef struct {
    uint32_t poly;
    uint32_t block;
    uint64_t byte_offset;
    uint64_t old_v;
    uint64_t new_v;
} mutation_info;

typedef struct {
    mutation_info mut;
    unsigned char pk_honest[BIT_PUBLICKEYBYTES];
    unsigned char pk_mutated[BIT_PUBLICKEYBYTES];
    unsigned char sig_mutated[BIT_SIGNBYTES];
    unsigned char msg[BIT_MESSAGEBYTES];
} tuple_data;

static int write_tuple(const char *path, const tuple_data *t) {
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    int ok = 1;
#define WF(ptr, size) do { if (fwrite((ptr), 1, (size), f) != (size)) ok = 0; } while (0)
    WF(TUPLE_MAGIC, TUPLE_MAGIC_LEN);
    unsigned char lengths[4][8];
    uint64_t lens[4] = {
        BIT_PUBLICKEYBYTES, BIT_SIGNBYTES, BIT_MESSAGEBYTES, BIT_SECRETKEYBYTES
    };
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) lengths[i][j] = (unsigned char)(lens[i] >> (8 * j));
    WF(lengths, sizeof(lengths));
    unsigned char mut[32];
    for (int j = 0; j < 4; j++) mut[j] = (unsigned char)(t->mut.poly >> (8 * j));
    for (int j = 0; j < 4; j++) mut[4 + j] = (unsigned char)(t->mut.block >> (8 * j));
    for (int j = 0; j < 8; j++) mut[8 + j] = (unsigned char)(t->mut.byte_offset >> (8 * j));
    for (int j = 0; j < 8; j++) mut[16 + j] = (unsigned char)(t->mut.old_v >> (8 * j));
    for (int j = 0; j < 8; j++) mut[24 + j] = (unsigned char)(t->mut.new_v >> (8 * j));
    WF(mut, sizeof(mut));
    WF(t->pk_honest, sizeof(t->pk_honest));
    WF(t->pk_mutated, sizeof(t->pk_mutated));
    WF(t->sig_mutated, sizeof(t->sig_mutated));
    WF(t->msg, sizeof(t->msg));
#undef WF
    if (fclose(f) != 0) ok = 0;
    return ok ? 0 : -1;
}

static uint64_t rd64(const unsigned char *p) {
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) x |= (uint64_t)p[i] << (8 * i);
    return x;
}

static uint32_t rd32(const unsigned char *p) {
    uint32_t x = 0;
    for (int i = 0; i < 4; i++) x |= (uint32_t)p[i] << (8 * i);
    return x;
}

static int read_tuple(const char *path, tuple_data *t) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "open %s: %s\n", path, strerror(errno));
        return -1;
    }
    unsigned char magic[TUPLE_MAGIC_LEN];
    unsigned char lens[32], mut[32];
    int ok = 1;
#define RF(ptr, size) do { if (fread((ptr), 1, (size), f) != (size)) ok = 0; } while (0)
    RF(magic, sizeof(magic));
    RF(lens, sizeof(lens));
    RF(mut, sizeof(mut));
    if (memcmp(magic, TUPLE_MAGIC, sizeof(magic)) != 0) ok = 0;
    if (rd64(lens) != BIT_PUBLICKEYBYTES ||
        rd64(lens + 8) != BIT_SIGNBYTES ||
        rd64(lens + 16) != BIT_MESSAGEBYTES ||
        rd64(lens + 24) != BIT_SECRETKEYBYTES) ok = 0;
    if (ok) {
        t->mut.poly = rd32(mut);
        t->mut.block = rd32(mut + 4);
        t->mut.byte_offset = rd64(mut + 8);
        t->mut.old_v = rd64(mut + 16);
        t->mut.new_v = rd64(mut + 24);
        RF(t->pk_honest, sizeof(t->pk_honest));
        RF(t->pk_mutated, sizeof(t->pk_mutated));
        RF(t->sig_mutated, sizeof(t->sig_mutated));
        RF(t->msg, sizeof(t->msg));
    }
#undef RF
    int trailing = fgetc(f);
    if (trailing != EOF) ok = 0;
    if (fclose(f) != 0) ok = 0;
    if (!ok) fprintf(stderr, "malformed tuple: %s\n", path);
    return ok ? 0 : -1;
}

static void sha256_cmd(const char *path, char out[65]) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "sha256sum -- '%s' 2>/dev/null", path);
    FILE *p = popen(cmd, "r");
    out[0] = '\0';
    if (p) {
        if (fscanf(p, "%64s", out) != 1) out[0] = '\0';
        pclose(p);
    }
}

static int decode_pk(const unsigned char *pk, polyveck *b1, unsigned char seed[BIT_SEEDBYTES]) {
    unpack_pk(seed, b1, pk);
    return 0;
}

static int first_coeff_diff(const polyveck *a, const polyveck *b, int *poly, int *coeff) {
    for (int i = 0; i < BIT_K; i++) {
        for (int j = 0; j < BIT_N; j++) {
            if (a->vec[i].coeffs[j] != b->vec[i].coeffs[j]) {
                *poly = i;
                *coeff = j;
                return 1;
            }
        }
    }
    return 0;
}

static void print_decode_report(const tuple_data *t) {
    polyveck honest, mutated;
    unsigned char seed_h[BIT_SEEDBYTES], seed_m[BIT_SEEDBYTES];
    decode_pk(t->pk_honest, &honest, seed_h);
    decode_pk(t->pk_mutated, &mutated, seed_m);
    int p = -1, j = -1;
    int diff = first_coeff_diff(&honest, &mutated, &p, &j);
    printf("decoder.honest_block_coeffs=%d,%d,%d,%d\n",
           honest.vec[t->mut.poly].coeffs[4 * t->mut.block],
           honest.vec[t->mut.poly].coeffs[4 * t->mut.block + 1],
           honest.vec[t->mut.poly].coeffs[4 * t->mut.block + 2],
           honest.vec[t->mut.poly].coeffs[4 * t->mut.block + 3]);
    printf("decoder.mutated_block_coeffs=%d,%d,%d,%d\n",
           mutated.vec[t->mut.poly].coeffs[4 * t->mut.block],
           mutated.vec[t->mut.poly].coeffs[4 * t->mut.block + 1],
           mutated.vec[t->mut.poly].coeffs[4 * t->mut.block + 2],
           mutated.vec[t->mut.poly].coeffs[4 * t->mut.block + 3]);
    printf("decoder.first_diff.exists=%d\n", diff);
    if (diff) {
        printf("decoder.first_diff.poly=%d\n", p);
        printf("decoder.first_diff.coeff=%d\n", j);
        printf("decoder.first_diff.honest=%d\n", honest.vec[p].coeffs[j]);
        printf("decoder.first_diff.mutated=%d\n", mutated.vec[p].coeffs[j]);
    }
}

static int init_deterministic_drng(void) {
    unsigned char seed[64];
    for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(0xa5U ^ (17U * (unsigned)i));
    return init_random_number(&drng_algorithm, seed, sizeof(seed));
}

static void init_message(unsigned char msg[BIT_MESSAGEBYTES]) {
    static const unsigned char prefix[] = "NGCC BiT-128 exact tuple test";
    memset(msg, 0, BIT_MESSAGEBYTES);
    memcpy(msg, prefix, sizeof(prefix) - 1);
}

static int generate_selftest(const char *outprefix) {
    unsigned char pk[BIT_PUBLICKEYBYTES], sk[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES], msg[BIT_MESSAGEBYTES];
    unsigned long long pklen = BIT_PUBLICKEYBYTES, sklen = BIT_SECRETKEYBYTES;
    unsigned long long siglen = BIT_SIGNBYTES;
    if (init_deterministic_drng() != 0) return -1;
    init_message(msg);
    int kg = bit_sig_keygen(pk, &pklen, sk, &sklen);
    int sg = bit_sig_sign(sk, sklen, msg, sizeof(msg), sig, &siglen);
    int vr = bit_sig_verify(sig, siglen, msg, sizeof(msg), pk, pklen);
    printf("mode=selftest\nimplementation=%s\nkeygen=%d\nsign=%d\nverify=%d\n", DRIVER_LABEL, kg, sg, vr);
    printf("lengths.pk=%llu,sk=%llu,sig=%llu,msg=%zu\n", pklen, sklen, siglen, sizeof(msg));
    if (outprefix) {
        char path[1024];
        FILE *f;
        snprintf(path, sizeof(path), "%s.pk", outprefix); f = fopen(path, "wb");
        if (f) { fwrite(pk, 1, pklen, f); fclose(f); }
        snprintf(path, sizeof(path), "%s.sk", outprefix); f = fopen(path, "wb");
        if (f) { fwrite(sk, 1, sklen, f); fclose(f); }
        snprintf(path, sizeof(path), "%s.sig", outprefix); f = fopen(path, "wb");
        if (f) { fwrite(sig, 1, siglen, f); fclose(f); }
        snprintf(path, sizeof(path), "%s.msg", outprefix); f = fopen(path, "wb");
        if (f) { fwrite(msg, 1, sizeof(msg), f); fclose(f); }
        char hpk[65], hsk[65], hsig[65];
        snprintf(path, sizeof(path), "%s.pk", outprefix); sha256_cmd(path, hpk);
        snprintf(path, sizeof(path), "%s.sk", outprefix); sha256_cmd(path, hsk);
        snprintf(path, sizeof(path), "%s.sig", outprefix); sha256_cmd(path, hsig);
        printf("sha256.pk=%s\nsha256.sk=%s\nsha256.sig=%s\n", hpk, hsk, hsig);
    }
    return (kg == 0 && sg == 0 && vr == 0) ? 0 : -1;
}

static int generate_tuple(const char *tuple_path, const char *tuple_sha_path) {
    unsigned char pk[BIT_PUBLICKEYBYTES], pk2[BIT_PUBLICKEYBYTES];
    unsigned char sk[BIT_SECRETKEYBYTES], sk2[BIT_SECRETKEYBYTES];
    unsigned char sig[BIT_SIGNBYTES], sig2[BIT_SIGNBYTES];
    unsigned char msg[BIT_MESSAGEBYTES];
    unsigned long long pklen = BIT_PUBLICKEYBYTES, sklen = BIT_SECRETKEYBYTES;
    unsigned long long siglen = BIT_SIGNBYTES;
    if (init_deterministic_drng() != 0) return -1;
    init_message(msg);
    int kg = bit_sig_keygen(pk, &pklen, sk, &sklen);
    int sg = bit_sig_sign(sk, sklen, msg, sizeof(msg), sig, &siglen);
    int canonical_verify = bit_sig_verify(sig, siglen, msg, sizeof(msg), pk, pklen);
    printf("mode=generate\nimplementation=%s\nkeygen=%d\ncanonical.sign=%d\ncanonical.verify=%d\n",
           DRIVER_LABEL, kg, sg, canonical_verify);

    int found = 0;
    mutation_info mut = {0};
    for (uint32_t p = 0; p < BIT_K && !found; p++) {
        for (uint32_t b = 0; b < BIT_N / 4; b++) {
            uint64_t bitpos = (uint64_t)b * 43;
            uint64_t byteoff = BIT_SEEDBYTES + (uint64_t)p * BIT_POLY_B1_BYTES + bitpos / 8;
            int shift = (int)(bitpos & 7);
            uint64_t raw = 0;
            for (int k = 0; k < 6; k++) raw |= (uint64_t)pk[byteoff + k] << (8 * k);
            uint64_t v = (raw >> shift) & MASK43;
            if (v + D4 < (1ULL << 43)) {
                mut.poly = p; mut.block = b; mut.byte_offset = byteoff;
                mut.old_v = v; mut.new_v = v + D4; found = 1; break;
            }
        }
    }
    if (!found) {
        printf("mutation.shared_43bit_block_exists=0\n");
        return -1;
    }

    memcpy(pk2, pk, sizeof(pk));
    uint64_t mask = MASK43 << (mut.byte_offset % 8);
    mut.byte_offset = BIT_SEEDBYTES + (uint64_t)mut.poly * BIT_POLY_B1_BYTES +
                      ((uint64_t)mut.block * 43) / 8;
    int shift = (int)(((uint64_t)mut.block * 43) & 7);
    mask = MASK43 << shift;
    uint64_t raw = 0;
    for (int k = 0; k < 6; k++) raw |= (uint64_t)pk2[mut.byte_offset + k] << (8 * k);
    raw = (raw & ~mask) | (mut.new_v << shift);
    for (int k = 0; k < 6; k++) pk2[mut.byte_offset + k] = (unsigned char)(raw >> (8 * k));

    memcpy(sk2, sk, sizeof(sk));
    bit_h256(sk2 + TR_OFFSET, pk2, BIT_PUBLICKEYBYTES);
    siglen = BIT_SIGNBYTES;
    int rebound_sign = bit_sig_sign(sk2, sklen, msg, sizeof(msg), sig2, &siglen);
    int rebound_verify = bit_sig_verify(sig2, siglen, msg, sizeof(msg), pk2, pklen);

    /* Negative control: a one-bit change to the same packed 43-bit block. */
    unsigned char pk3[BIT_PUBLICKEYBYTES];
    unsigned char sig3[BIT_SIGNBYTES];
    unsigned char sk3[BIT_SECRETKEYBYTES];
    memcpy(pk3, pk, sizeof(pk));
    raw = 0;
    for (int k = 0; k < 6; k++) raw |= (uint64_t)pk3[mut.byte_offset + k] << (8 * k);
    uint64_t onebit_v = (mut.old_v ^ 1ULL);
    raw = (raw & ~mask) | (onebit_v << shift);
    for (int k = 0; k < 6; k++) pk3[mut.byte_offset + k] = (unsigned char)(raw >> (8 * k));
    memcpy(sk3, sk, sizeof(sk));
    bit_h256(sk3 + TR_OFFSET, pk3, BIT_PUBLICKEYBYTES);
    unsigned long long sig3len = BIT_SIGNBYTES;
    int control_sign = bit_sig_sign(sk3, sklen, msg, sizeof(msg), sig3, &sig3len);
    int control_verify = bit_sig_verify(sig3, sig3len, msg, sizeof(msg), pk3, pklen);

    tuple_data t;
    memset(&t, 0, sizeof(t));
    t.mut = mut;
    memcpy(t.pk_honest, pk, sizeof(t.pk_honest));
    memcpy(t.pk_mutated, pk2, sizeof(t.pk_mutated));
    memcpy(t.sig_mutated, sig2, sizeof(t.sig_mutated));
    memcpy(t.msg, msg, sizeof(t.msg));
    if (write_tuple(tuple_path, &t) != 0) return -1;
    char sidepath[1024];
    FILE *sf;
    snprintf(sidepath, sizeof(sidepath), "%s.sk.original", tuple_path);
    sf = fopen(sidepath, "wb");
    if (sf) { fwrite(sk, 1, sizeof(sk), sf); fclose(sf); }
    snprintf(sidepath, sizeof(sidepath), "%s.sk.rebound", tuple_path);
    sf = fopen(sidepath, "wb");
    if (sf) { fwrite(sk2, 1, sizeof(sk2), sf); fclose(sf); }
    snprintf(sidepath, sizeof(sidepath), "%s.sig.rebound", tuple_path);
    sf = fopen(sidepath, "wb");
    if (sf) { fwrite(sig2, 1, sizeof(sig2), sf); fclose(sf); }
    snprintf(sidepath, sizeof(sidepath), "%s.pk.honest", tuple_path);
    sf = fopen(sidepath, "wb");
    if (sf) { fwrite(pk, 1, sizeof(pk), sf); fclose(sf); }
    snprintf(sidepath, sizeof(sidepath), "%s.pk.mutated", tuple_path);
    sf = fopen(sidepath, "wb");
    if (sf) { fwrite(pk2, 1, sizeof(pk2), sf); fclose(sf); }
    snprintf(sidepath, sizeof(sidepath), "%s.msg", tuple_path);
    sf = fopen(sidepath, "wb");
    if (sf) { fwrite(msg, 1, sizeof(msg), sf); fclose(sf); }
    char htuple[65];
    sha256_cmd(tuple_path, htuple);
    if (tuple_sha_path) {
        FILE *f = fopen(tuple_sha_path, "w");
        if (f) { fprintf(f, "%s  %s\n", htuple, tuple_path); fclose(f); }
    }

    printf("mutation.shared_43bit_block_exists=1\n");
    printf("mutation.poly=%u\nmutation.block=%u\n", mut.poly, mut.block);
    printf("mutation.pk_byte_offset=%" PRIu64 "\n", mut.byte_offset);
    printf("mutation.old_v=%" PRIu64 "\nmutation.new_v=%" PRIu64 "\n", mut.old_v, mut.new_v);
    printf("mutation.D4=%" PRIu64 "\nmutation.new_v_lt_2pow43=%d\n",
           (uint64_t)D4, mut.new_v < (1ULL << 43));
    printf("transcript.sk_offset=%d\n", TR_OFFSET);
    print_decode_report(&t);
    printf("rebound.sign=%d\nrebound.verify=%d\n", rebound_sign, rebound_verify);
    printf("onebit.control.sign=%d\nonebit.control.verify=%d\n", control_sign, control_verify);
    printf("tuple.path=%s\ntuple.sha256=%s\n", tuple_path, htuple);
    return 0;
}

static int verify_tuple_file(const char *tuple_path) {
    tuple_data t;
    if (read_tuple(tuple_path, &t) != 0) return -1;
    printf("mode=verify-tuple\nimplementation=%s\ntuple.path=%s\n", DRIVER_LABEL, tuple_path);
    print_decode_report(&t);
    int vr = bit_sig_verify(t.sig_mutated, BIT_SIGNBYTES, t.msg, BIT_MESSAGEBYTES,
                            t.pk_mutated, BIT_PUBLICKEYBYTES);
    printf("mutated_tuple.verify=%d\n", vr);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s selftest [outprefix] | generate tuple.bin [tuple.sha256] | verify tuple.bin\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "selftest") == 0) {
        return generate_selftest(argc >= 3 ? argv[2] : NULL) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "generate") == 0 && argc >= 3) {
        return generate_tuple(argv[2], argc >= 4 ? argv[3] : NULL) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "verify") == 0 && argc >= 3) {
        return verify_tuple_file(argv[2]) == 0 ? 0 : 1;
    }
    fprintf(stderr, "invalid arguments\n");
    return 2;
}
