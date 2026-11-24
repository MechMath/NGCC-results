#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "faest.h"

DRNG_ctx drng_algorithm;

static void vm_sizes_kib(unsigned long *rss, unsigned long *vsize)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long value = 0;
    unsigned long size = 0;
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "VmRSS: %lu kB", &value) == 1)
            continue;
        if (sscanf(line, "VmSize: %lu kB", &size) == 1)
            continue;
    }
    fclose(f);
    *rss = value;
    *vsize = size;
}

static void die(const char *what)
{
    fprintf(stderr, "%s: %s\n", what, strerror(errno));
    exit(2);
}

static unsigned char *read_exact(const char *path, size_t n)
{
    FILE *f = fopen(path, "rb");
    unsigned char *p;
    if (!f)
        die(path);
    p = malloc(n);
    if (!p)
        die("malloc");
    if (fread(p, 1, n, f) != n)
        die("short read");
    if (fgetc(f) != EOF)
        die("trailing bytes");
    if (fclose(f))
        die("close");
    return p;
}

int main(int argc, char **argv)
{
    const size_t pk_len = sig_get_pk_len_bytes();
    const size_t sig_len = sig_get_sn_len_bytes();
    const size_t msg_len = 15;
    const size_t delta_byte_mask = (size_t)1 << 7;
    const size_t delta_forbidden_byte =
        VOLE_COMMIT_SIZE + VOLE_CHECK_PROOF_BYTES + WITNESS_BITS / 8 +
        QUICKSILVER_PROOF_BYTES + VECTOR_COM_OPEN_SIZE + sizeof(block_secpar) - 1;
    char path[1024];
    unsigned char *pk;
    unsigned char *sig;
    unsigned char *msg;
    unsigned long count = 1;
    unsigned long rss_before, vsize_before, rss_after, vsize_after;
    int ret = -99;

    if ((argc != 3 && argc != 4) ||
        (strcmp(argv[1], "honest") && strcmp(argv[1], "forbidden-delta")))
        die("usage: leak_harness honest|forbidden-delta CASE_PREFIX [COUNT]");
    if (argc == 4) {
        char *end = NULL;
        count = strtoul(argv[3], &end, 10);
        if (!end || *end || count == 0)
            die("invalid COUNT");
    }
    if (sig_len != FAEST_SIGNATURE_BYTES || delta_forbidden_byte != 2737) {
        fprintf(stderr, "layout mismatch sig=%zu forbidden_byte=%zu\n",
                sig_len, delta_forbidden_byte);
        return 3;
    }

    snprintf(path, sizeof(path), "%s.pk", argv[2]);
    pk = read_exact(path, pk_len);
    snprintf(path, sizeof(path), "%s.sig", argv[2]);
    sig = read_exact(path, sig_len);
    snprintf(path, sizeof(path), "%s.msg", argv[2]);
    msg = read_exact(path, msg_len);

    if (!strcmp(argv[1], "forbidden-delta"))
        sig[delta_forbidden_byte] |= delta_byte_mask;

    vm_sizes_kib(&rss_before, &vsize_before);
    for (unsigned long i = 0; i < count; ++i)
        ret = sig_verify(pk, pk_len, sig, sig_len, msg, msg_len);
    vm_sizes_kib(&rss_after, &vsize_after);
    printf("mode=%s ret=%d count=%lu sig_len=%zu forbidden_byte=%zu rss_before_kib=%lu rss_after_kib=%lu rss_growth_kib=%lu vsize_before_kib=%lu vsize_after_kib=%lu vsize_growth_kib=%lu\n",
           argv[1], ret, count, sig_len, delta_forbidden_byte,
           rss_before, rss_after, rss_after - rss_before,
           vsize_before, vsize_after, vsize_after - vsize_before);
    free(msg);
    free(sig);
    free(pk);
    return 0;
}
