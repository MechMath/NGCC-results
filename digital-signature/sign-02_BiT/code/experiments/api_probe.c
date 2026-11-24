#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

#define MSG_LEN 64

static void die(const char *what) {
    fprintf(stderr, "api_probe: %s: %s\n", what, strerror(errno));
    exit(2);
}

static void put_u64(unsigned char *p, uint64_t x) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(x >> (8 * i));
}

static uint64_t get_u64(const unsigned char *p) {
    uint64_t x = 0;
    for (unsigned i = 0; i < 8; i++) x |= (uint64_t)p[i] << (8 * i);
    return x;
}

static void write_file(const char *path, const void *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) die(path);
    if (len && fwrite(buf, 1, len, f) != len) die(path);
    if (fclose(f) != 0) die(path);
}

static unsigned char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    long n;
    unsigned char *buf;
    if (!f) die(path);
    if (fseek(f, 0, SEEK_END) != 0) die(path);
    n = ftell(f);
    if (n < 0) die(path);
    if (fseek(f, 0, SEEK_SET) != 0) die(path);
    buf = malloc((size_t)n ? (size_t)n : 1);
    if (!buf) die("malloc");
    if (n && fread(buf, 1, (size_t)n, f) != (size_t)n) die(path);
    if (fclose(f) != 0) die(path);
    *len = (size_t)n;
    return buf;
}

typedef struct {
    unsigned char *pk;
    unsigned char *sig;
    unsigned char *msg;
    size_t pk_len;
    size_t sig_len;
    size_t msg_len;
} bundle;

static bundle load_bundle(const char *path) {
    bundle b = {0};
    size_t n;
    unsigned char *raw = read_file(path, &n);
    if (n < 24) {
        fprintf(stderr, "api_probe: short bundle\n");
        exit(2);
    }
    b.pk_len = (size_t)get_u64(raw);
    b.sig_len = (size_t)get_u64(raw + 8);
    b.msg_len = (size_t)get_u64(raw + 16);
    if (24 + b.pk_len + b.sig_len + b.msg_len != n) {
        fprintf(stderr, "api_probe: bundle length mismatch\n");
        exit(2);
    }
    b.pk = raw + 24;
    b.sig = b.pk + b.pk_len;
    b.msg = b.sig + b.sig_len;
    return b;
}

static void cmd_gen(const char *prefix) {
    const size_t pk_cap = (size_t)sig_get_pk_len_bytes();
    const size_t sk_cap = (size_t)sig_get_sk_len_bytes();
    const size_t sig_cap = (size_t)sig_get_sn_len_bytes();
    unsigned char seed[64];
    unsigned char msg[MSG_LEN];
    unsigned char *pk = calloc(pk_cap, 1);
    unsigned char *sk = calloc(sk_cap, 1);
    unsigned char *sig = calloc(sig_cap, 1);
    unsigned char *bundle_buf;
    unsigned long long pk_len = (unsigned long long)pk_cap;
    unsigned long long sk_len = (unsigned long long)sk_cap;
    unsigned long long sig_len = (unsigned long long)sig_cap;
    char path[1024];
    int r;
    if (!pk || !sk || !sig) die("calloc");

    for (unsigned i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)i;
    for (unsigned i = 0; i < sizeof(msg); i++) msg[i] = (unsigned char)(0xa5 ^ (i * 17));
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "api_probe: drng init failed\n");
        exit(2);
    }
    r = sig_keygen(pk, &pk_len, sk, &sk_len);
    if (r != 0) {
        fprintf(stderr, "api_probe: keygen failed %d\n", r);
        exit(3);
    }
    r = sig_sign(sk, sk_len, msg, MSG_LEN, sig, &sig_len);
    if (r != 0) {
        fprintf(stderr, "api_probe: sign failed %d\n", r);
        exit(3);
    }
    r = sig_verify(pk, pk_len, sig, sig_len, msg, MSG_LEN);
    if (r != 0) {
        fprintf(stderr, "api_probe: self verify failed %d\n", r);
        exit(3);
    }
    if (pk_len != pk_cap || sk_len != sk_cap || sig_len != sig_cap) {
        fprintf(stderr, "api_probe: length mismatch\n");
        exit(3);
    }
    bundle_buf = malloc(24 + pk_len + sig_len + MSG_LEN);
    if (!bundle_buf) die("malloc");
    put_u64(bundle_buf, pk_len);
    put_u64(bundle_buf + 8, sig_len);
    put_u64(bundle_buf + 16, MSG_LEN);
    memcpy(bundle_buf + 24, pk, pk_len);
    memcpy(bundle_buf + 24 + pk_len, sig, sig_len);
    memcpy(bundle_buf + 24 + pk_len + sig_len, msg, MSG_LEN);
    snprintf(path, sizeof(path), "%s.bin", prefix);
    write_file(path, bundle_buf, 24 + pk_len + sig_len + MSG_LEN);
    printf("instance=%s pk_len=%llu sk_len=%llu sig_len=%llu message_len=%d baseline_verify=0 bundle=%s\n",
           ALGORITHM_INSTANCE, pk_len, sk_len, sig_len, MSG_LEN, path);
    free(bundle_buf);
    free(sig);
    free(sk);
    free(pk);
}

typedef struct {
    FILE *csv;
    unsigned long long cases;
    unsigned long long accepted;
    unsigned long long crashes;
} test_ctx;

static unsigned char *copy_sig;
static unsigned char *copy_pk;
static unsigned char *copy_msg;
static size_t cur_sig_len;
static size_t cur_pk_len;
static size_t cur_msg_len;

static void run_case(test_ctx *t, const char *family, size_t index,
                     unsigned old_sig, unsigned new_sig,
                     unsigned old_pk, unsigned new_pk,
                     int pk_changed, int sig_changed) {
    int r = sig_verify(copy_pk, (unsigned long long)cur_pk_len,
                       copy_sig, (unsigned long long)cur_sig_len,
                       copy_msg, (unsigned long long)cur_msg_len);
    int accepted = (r == 0);
    fprintf(t->csv, "%llu,%s,%zu,%u,%u,%u,%u,%d,%d,%d,%d\n",
            t->cases, family, index, old_sig, new_sig, old_pk, new_pk,
            pk_changed, sig_changed, r, accepted);
    t->cases++;
    if (accepted) t->accepted++;
}

static void restore_sig(const unsigned char *orig) {
    memcpy(copy_sig, orig, cur_sig_len);
}

static void restore_pk(const unsigned char *orig) {
    memcpy(copy_pk, orig, cur_pk_len);
}

static void sample_byte_mutations(test_ctx *t, const char *family,
                                  size_t region, size_t start, size_t len) {
    static const unsigned vals[] = {1, 3, 0x80, 0xff};
    size_t probes[64];
    size_t np = 0;
    if (len == 0) return;
    for (size_t i = start; i < start + len && i < cur_sig_len && np < 30; i += (len > 29 ? (len - 1) / 29 : 1)) {
        probes[np++] = i;
    }
    if (np < 64 && start + len - 1 < cur_sig_len) probes[np++] = start + len - 1;
    for (size_t j = 0; j < np; j++) {
        size_t i = probes[j];
        unsigned old = copy_sig[i];
        for (size_t k = 0; k < sizeof(vals) / sizeof(vals[0]); k++) {
            unsigned nv = (old ^ vals[k]) & 0xff;
            copy_sig[i] = (unsigned char)nv;
            run_case(t, family, i, old, nv, 0, 0, 0, 1);
            copy_sig[i] = (unsigned char)old;
        }
    }
    for (size_t i = start; i < start + len; i++) {
        unsigned old = copy_sig[i];
        unsigned nv = (old + 243) & 0xff;
        copy_sig[i] = (unsigned char)nv;
        run_case(t, "hint_plus_243", i, old, nv, 0, 0, 0, 1);
        copy_sig[i] = (unsigned char)old;
    }
}

static uint64_t next_rand(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return *s = x;
}

static void cmd_mutate(const char *bundle_path, const char *out_path) {
    bundle b = load_bundle(bundle_path);
    unsigned char *orig_sig;
    unsigned char *orig_pk;
    test_ctx t = {0};
    uint64_t rng = UINT64_C(0x6a09e667f3bcc909);
    int r;
    t.csv = fopen(out_path, "w");
    if (!t.csv) die(out_path);
    fprintf(t.csv, "case,family,index,old_sig,new_sig,old_pk,new_pk,pk_changed,sig_changed,return,accepted\n");

    copy_pk = malloc(b.pk_len);
    copy_sig = malloc(b.sig_len);
    if (!copy_pk || !copy_sig) die("malloc");
    cur_pk_len = b.pk_len;
    cur_sig_len = b.sig_len;
    cur_msg_len = b.msg_len;
    copy_msg = b.msg;
    memcpy(copy_pk, b.pk, b.pk_len);
    memcpy(copy_sig, b.sig, b.sig_len);
    orig_pk = malloc(b.pk_len);
    orig_sig = malloc(b.sig_len);
    if (!orig_pk || !orig_sig) die("malloc");
    memcpy(orig_pk, b.pk, b.pk_len);
    memcpy(orig_sig, b.sig, b.sig_len);

    r = sig_verify(copy_pk, cur_pk_len, copy_sig, cur_sig_len, b.msg, b.msg_len);
    fprintf(t.csv, "%llu,positive_control,-1,0,0,0,0,0,0,%d,%d\n", t.cases, r, r == 0);
    t.cases++;
    if (r == 0) t.accepted++;
    memset(copy_sig, 0, cur_sig_len);
    r = sig_verify(copy_pk, cur_pk_len, copy_sig, cur_sig_len, b.msg, b.msg_len);
    fprintf(t.csv, "%llu,negative_all_zero,-1,0,0,0,0,0,1,%d,%d\n", t.cases, r, r == 0);
    t.cases++;
    restore_sig(orig_sig);

    {
        int rr = sig_verify(copy_pk, cur_pk_len, copy_sig, cur_sig_len - 1, b.msg, b.msg_len);
        fprintf(t.csv, "%llu,length_sig_minus1,-1,0,0,0,0,0,1,%d,%d\n", t.cases, rr, rr == 0);
        t.cases++;
        rr = sig_verify(copy_pk, cur_pk_len, copy_sig, cur_sig_len + 1, b.msg, b.msg_len);
        fprintf(t.csv, "%llu,length_sig_plus1,-1,0,0,0,0,0,1,%d,%d\n", t.cases, rr, rr == 0);
        t.cases++;
    }

    sample_byte_mutations(&t, "challenge", 0, 0, BIT_CHALLENGEBYTES);
    sample_byte_mutations(&t, "z0", 1, BIT_CHALLENGEBYTES, BIT_POLY_Z0_BYTES);
    sample_byte_mutations(&t, "z1", 2, BIT_CHALLENGEBYTES + BIT_POLY_Z0_BYTES,
                          BIT_POLYVECL_Z1_BYTES);
    sample_byte_mutations(&t, "hint", 3,
                          BIT_CHALLENGEBYTES + BIT_POLY_Z0_BYTES + BIT_POLYVECL_Z1_BYTES,
                          BIT_POLYVECK_H_BYTES);

    for (int n = 0; n < 256; n++) {
        size_t i = (size_t)(next_rand(&rng) % cur_sig_len);
        unsigned old = copy_sig[i];
        unsigned nv = (unsigned)(next_rand(&rng) & 0xff);
        copy_sig[i] = (unsigned char)nv;
        run_case(&t, "seeded_single_sig", i, old, nv, 0, 0, 0, 1);
        copy_sig[i] = (unsigned char)old;
    }
    for (int n = 0; n < 64; n++) {
        size_t i = (size_t)(next_rand(&rng) % cur_pk_len);
        unsigned old = copy_pk[i];
        unsigned nv = (unsigned)(next_rand(&rng) & 0xff);
        copy_pk[i] = (unsigned char)nv;
        run_case(&t, "seeded_single_pk", i, 0, 0, old, nv, 1, 0);
        copy_pk[i] = (unsigned char)old;
    }
    for (size_t i = 0; i < BIT_SEEDBYTES && i < cur_pk_len; i += (BIT_SEEDBYTES > 16 ? BIT_SEEDBYTES / 16 : 1)) {
        unsigned old = copy_pk[i];
        copy_pk[i] ^= 1;
        run_case(&t, "pk_seed", i, 0, 0, old, copy_pk[i], 1, 0);
        copy_pk[i] = (unsigned char)old;
    }
    for (int n = 0; n < 32; n++) {
        size_t i = BIT_SEEDBYTES + (size_t)n * (cur_pk_len - BIT_SEEDBYTES) / 32;
        if (i >= cur_pk_len) break;
        unsigned old = copy_pk[i];
        copy_pk[i] ^= 1;
        run_case(&t, "pk_block", i, 0, 0, old, copy_pk[i], 1, 0);
        copy_pk[i] = (unsigned char)old;
    }
    for (int n = 0; n < 32; n++) {
        size_t i1 = (size_t)(next_rand(&rng) % cur_sig_len);
        size_t i2 = (size_t)(next_rand(&rng) % cur_sig_len);
        unsigned old1 = copy_sig[i1], old2 = copy_sig[i2];
        copy_sig[i1] ^= 0x55;
        copy_sig[i2] ^= 0xaa;
        run_case(&t, "seeded_double_sig", i1, old1, copy_sig[i1], old2, copy_sig[i2], 0, 1);
        restore_sig(orig_sig);
    }
    fclose(t.csv);
    restore_pk(orig_pk);
    printf("instance=%s source_bundle=%s cases=%llu accepted=%llu output=%s\n",
           ALGORITHM_INSTANCE, bundle_path, t.cases, t.accepted, out_path);
    free(orig_sig);
    free(orig_pk);
    free(copy_sig);
    free(copy_pk);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "gen") == 0) {
        cmd_gen(argv[2]);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "mutate") == 0) {
        cmd_mutate(argv[2], argv[3]);
        return 0;
    }
    fprintf(stderr, "usage: %s gen PREFIX | mutate BUNDLE OUT.csv\n", argv[0]);
    return 2;
}
