#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

#define MESSAGE_LEN 5000U
#define MAX_PRESSURE_CHUNKS 65536U

static void *pressure_chunks[MAX_PRESSURE_CHUNKS];
static size_t pressure_count;

static void die(const char *what)
{
    fprintf(stderr, "FATAL: %s: %s\n", what, strerror(errno));
    exit(2);
}

static void print_status(const char *label)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[512];

    if (f == NULL) {
        die("fopen /proc/self/status");
    }
    printf("[status:%s]\n", label);
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "VmSize:", 7) == 0 ||
            strncmp(line, "VmRSS:", 6) == 0 ||
            strncmp(line, "VmPeak:", 7) == 0 ||
            strncmp(line, "VmData:", 7) == 0 ||
            strncmp(line, "VmStk:", 6) == 0) {
            fputs(line, stdout);
        }
    }
    fclose(f);
}

static void init_submitted_drng(void)
{
    unsigned char seed[64];

    for (size_t i = 0; i < sizeof(seed); i++) {
        seed[i] = (unsigned char)(0xA0U + (unsigned char)i);
    }
    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
        fprintf(stderr, "FATAL: init_random_number failed\n");
        exit(3);
    }
}

static void fill_message(unsigned char *msg, unsigned char marker)
{
    for (size_t i = 0; i < MESSAGE_LEN; i++) {
        msg[i] = (unsigned char)(marker ^ (unsigned char)(i * 131U));
    }
}

static void hold_pressure_chunks(size_t chunk_size, size_t count)
{
    for (size_t i = 0; i < count && pressure_count < MAX_PRESSURE_CHUNKS; i++) {
        void *p = malloc(chunk_size);
        if (p == NULL) {
            printf("pressure_chunk_stop index=%zu requested=%zu errno=%d (%s)\n",
                   i, chunk_size, errno, strerror(errno));
            return;
        }
        memset(p, 0xA5, chunk_size);
        pressure_chunks[pressure_count++] = p;
    }
    printf("pressure_chunks_held count=%zu chunk_size=%zu bytes=%zu\n",
           pressure_count, chunk_size, pressure_count * chunk_size);
}

static void fill_remaining_address_space(size_t step)
{
    size_t balloon_count = 0;
    size_t balloon_bytes = 0;

    while (pressure_count < MAX_PRESSURE_CHUNKS) {
        void *p = malloc(step);
        if (p == NULL) {
            printf("balloon_stop count=%zu bytes=%zu requested=%zu errno=%d (%s)\n",
                   balloon_count, balloon_bytes, step, errno, strerror(errno));
            return;
        }
        memset(p, 0x5A, step);
        pressure_chunks[pressure_count++] = p;
        balloon_count++;
        balloon_bytes += step;
    }
    printf("balloon_capacity_exhausted count=%zu bytes=%zu\n",
           balloon_count, balloon_bytes);
}

static void release_pressure(void)
{
    while (pressure_count != 0) {
        free(pressure_chunks[--pressure_count]);
        pressure_chunks[pressure_count] = NULL;
    }
    printf("pressure_released\n");
    (void)malloc_trim(0);
    printf("malloc_trim_complete\n");
}

static void probe_target_allocation(size_t size)
{
    void *p = malloc(size);

    if (p == NULL) {
        printf("target_probe failed requested=%zu errno=%d (%s)\n",
               size, errno, strerror(errno));
        return;
    }
    printf("target_probe succeeded requested=%zu\n", size);
    free(p);
}

static void write_hex_file(const char *path, const unsigned char *buf, size_t len)
{
    FILE *f = fopen(path, "w");

    if (f == NULL) {
        die("fopen signature output");
    }
    for (size_t i = 0; i < len; i++) {
        fprintf(f, "%02x", buf[i]);
    }
    fputc('\n', f);
    fclose(f);
}

int main(int argc, char **argv)
{
    const char *prefix = argc > 1 ? argv[1] : "run";
    size_t chunk_size = argc > 2 ? strtoull(argv[2], NULL, 0) : 8192U;
    size_t chunk_count = argc > 3 ? strtoull(argv[3], NULL, 0) : 4096U;
    size_t balloon_step = argc > 4 ? strtoull(argv[4], NULL, 0) : 1048576U;
    struct rlimit as_limit;
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sig1_len = sig_get_sn_len_bytes();
    unsigned long long sig2_len = sig_get_sn_len_bytes();
    unsigned long long sig3_len = sig_get_sn_len_bytes();
    unsigned char *pk = malloc((size_t)pk_len);
    unsigned char *sk = malloc((size_t)sk_len);
    unsigned char *sig1 = malloc((size_t)sig1_len);
    unsigned char *sig2 = malloc((size_t)sig2_len);
    unsigned char *sig3 = malloc((size_t)sig3_len);
    unsigned char *m1 = malloc(MESSAGE_LEN);
    unsigned char *m2 = malloc(MESSAGE_LEN);
    char sig2_path[512];
    int rc;

    if (pk == NULL || sk == NULL || sig1 == NULL || sig2 == NULL ||
        sig3 == NULL || m1 == NULL || m2 == NULL) {
        die("initial harness allocation");
    }
    fill_message(m1, 0x11);
    fill_message(m2, 0x77);

    if (getrlimit(RLIMIT_AS, &as_limit) != 0) {
        die("getrlimit");
    }
    printf("prefix=%s\n", prefix);
    printf("pid=%ld message_len=%u pk_len=%llu sk_len=%llu sig_len=%llu\n",
           (long)getpid(), MESSAGE_LEN, pk_len, sk_len, sig1_len);
    printf("rlimit_as soft=%llu hard=%llu\n",
           (unsigned long long)as_limit.rlim_cur,
           (unsigned long long)as_limit.rlim_max);
    print_status("start");

    init_submitted_drng();
    rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    printf("keygen_rc=%d pk_len=%llu sk_len=%llu\n", rc, pk_len, sk_len);
    if (rc != 0) {
        return 10;
    }
    print_status("after_keygen");

    rc = sig_sign(sk, sk_len, m1, MESSAGE_LEN, sig1, &sig1_len);
    printf("sign1_rc=%d sig1_len=%llu\n", rc, sig1_len);
    printf("sign1_vs_m1=%d sign1_vs_m2=%d\n",
           sig_verify(pk, pk_len, sig1, sig1_len, m1, MESSAGE_LEN),
           sig_verify(pk, pk_len, sig1, sig1_len, m2, MESSAGE_LEN));
    if (rc != 0) {
        return 11;
    }
    print_status("after_sign1");

    hold_pressure_chunks(chunk_size, chunk_count);
    fill_remaining_address_space(balloon_step);
    probe_target_allocation((size_t)BIT_TRBYTES + MESSAGE_LEN);
    print_status("before_sign2_pressure");

    rc = sig_sign(sk, sk_len, m2, MESSAGE_LEN, sig2, &sig2_len);
    printf("sign2_rc=%d sig2_len=%llu\n", rc, sig2_len);
    snprintf(sig2_path, sizeof(sig2_path), "%s.sig2.hex", prefix);
    write_hex_file(sig2_path, sig2, (size_t)sig2_len);

    release_pressure();
    print_status("after_pressure_release");
    printf("sign2_vs_m1=%d sign2_vs_m2=%d\n",
           sig_verify(pk, pk_len, sig2, sig2_len, m1, MESSAGE_LEN),
           sig_verify(pk, pk_len, sig2, sig2_len, m2, MESSAGE_LEN));

    rc = sig_sign(sk, sk_len, m2, MESSAGE_LEN, sig3, &sig3_len);
    printf("sign3_nopressure_rc=%d sig3_len=%llu\n", rc, sig3_len);
    printf("sign3_vs_m1=%d sign3_vs_m2=%d\n",
           sig_verify(pk, pk_len, sig3, sig3_len, m1, MESSAGE_LEN),
           sig_verify(pk, pk_len, sig3, sig3_len, m2, MESSAGE_LEN));
    print_status("end");

    free(m2);
    free(m1);
    free(sig3);
    free(sig2);
    free(sig1);
    free(sk);
    free(pk);
    return 0;
}
