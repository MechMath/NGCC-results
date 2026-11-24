#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include "kem.h"

#define MAX_BYTES 32768
#define MAX_REPS 2000

static const unsigned char *g_secret_key;
static volatile uint64_t g_selected_sigma;
static volatile uint64_t g_selected_mprime;
static volatile uint64_t g_kdf_calls;

int __real_bike_hash(unsigned char *out, size_t outlen,
                     const unsigned char *in, size_t inlen);

int __wrap_bike_hash(unsigned char *out, size_t outlen,
                     const unsigned char *in, size_t inlen)
{
  if(inlen == ELL_SIZE + CRYPTO_CIPHERTEXTBYTES && g_secret_key != NULL) {
    const unsigned char *sigma = g_secret_key + 2 * R_SIZE;
    if(memcmp(in, sigma, ELL_SIZE) == 0) {
      g_selected_sigma++;
    } else {
      g_selected_mprime++;
    }
  }
  g_kdf_calls++;
  return __real_bike_hash(out, outlen, in, inlen);
}

static int hex_value(char c)
{
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'a' && c <= 'f') return 10 + c - 'a';
  if(c >= 'A' && c <= 'F') return 10 + c - 'A';
  return -1;
}

static int read_hex_field(FILE *f, const char *field, uint8_t *out,
                          size_t cap, size_t *out_len)
{
  char *line = NULL;
  size_t line_cap = 0;
  ssize_t n;
  const size_t field_len = strlen(field);

  while((n = getline(&line, &line_cap, f)) >= 0) {
    if((size_t)n > field_len && strncmp(line, field, field_len) == 0) {
      const char *hex = line + field_len;
      const size_t hex_len = strcspn(hex, "\r\n");
      if((hex_len & 1U) != 0 || hex_len / 2U > cap) {
        free(line);
        return -1;
      }
      for(size_t i = 0; i < hex_len / 2U; i++) {
        const int hi = hex_value(hex[2U * i]);
        const int lo = hex_value(hex[2U * i + 1U]);
        if(hi < 0 || lo < 0) {
          free(line);
          return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
      }
      *out_len = hex_len / 2U;
      free(line);
      return 0;
    }
  }
  free(line);
  return -1;
}

static uint64_t rng_state = UINT64_C(0xd1b54a32d192ed03);

static uint64_t rng64(void)
{
  uint64_t x = rng_state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  rng_state = x;
  return x;
}

static uint64_t thread_ns(void)
{
  struct timespec ts;
  if(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static uint64_t monotonic_ns(void)
{
  struct timespec ts;
  if(clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) abort();
  return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b)
{
  const uint64_t x = *(const uint64_t *)a;
  const uint64_t y = *(const uint64_t *)b;
  return (x > y) - (x < y);
}

static double median(uint64_t *x, size_t n)
{
  qsort(x, n, sizeof(*x), cmp_u64);
  return n & 1U ? (double)x[n / 2]
                : 0.5 * ((double)x[n / 2 - 1] + (double)x[n / 2]);
}

static uint64_t time_decode(unsigned char *ss, const unsigned char *ct,
                            const unsigned char *sk, int use_thread_clock)
{
  const uint64_t t0 = use_thread_clock ? thread_ns() : monotonic_ns();
  const int rc = crypto_kem_dec(ss, ct, sk);
  const uint64_t t1 = use_thread_clock ? thread_ns() : monotonic_ns();
  if(rc != 0) {
    fprintf(stderr, "crypto_kem_dec rc=%d\n", rc);
    exit(3);
  }
  return t1 - t0;
}

static void pin_and_lock(void)
{
  const int cpu = sched_getcpu();
  if(cpu >= 0) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if(sched_setaffinity(0, sizeof(set), &set) != 0) {
      fprintf(stderr, "warning: sched_setaffinity failed: %s\n",
              strerror(errno));
    }
    printf("pinned_cpu=%d\n", cpu);
  }
  if(mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
    fprintf(stderr, "warning: mlockall failed: %s\n", strerror(errno));
  }
}

int main(int argc, char **argv)
{
  static uint8_t sk[MAX_BYTES];
  static uint8_t ct[MAX_BYTES];
  static uint8_t expected_ss[MAX_BYTES];
  static uint8_t ss[MAX_BYTES];
  static uint8_t bad_c1[MAX_BYTES];
  static uint64_t valid_ns[MAX_REPS];
  static uint64_t fail_ns[MAX_REPS];
  static double ratios[MAX_REPS];
  size_t sk_len = 0, ct_len = 0, ss_len = 0;
  uint32_t reps = 600;

  if(argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s KAT.txt [pairs<=%d]\n", argv[0], MAX_REPS);
    return 2;
  }
  if(argc == 3) {
    const unsigned long v = strtoul(argv[2], NULL, 10);
    if(v < 10 || v > MAX_REPS) return 2;
    reps = (uint32_t)v;
  }

  FILE *f = fopen(argv[1], "rb");
  if(f == NULL) {
    perror("fopen");
    return 2;
  }
  if(read_hex_field(f, "SK = ", sk, sizeof(sk), &sk_len) != 0 ||
     read_hex_field(f, "CT = ", ct, sizeof(ct), &ct_len) != 0 ||
     read_hex_field(f, "SS = ", expected_ss, sizeof(expected_ss), &ss_len) != 0) {
    fprintf(stderr, "failed to parse KAT\n");
    return 2;
  }
  fclose(f);
  if(sk_len != CRYPTO_SECRETKEYBYTES || ct_len != CRYPTO_CIPHERTEXTBYTES ||
     ss_len != CRYPTO_BYTES) {
    fprintf(stderr, "length mismatch sk=%zu ct=%zu ss=%zu\n",
            sk_len, ct_len, ss_len);
    return 2;
  }

  memcpy(bad_c1, ct, ct_len);
  bad_c1[ct_len - 1] ^= 1U;
  g_secret_key = sk;
  pin_and_lock();

  if(crypto_kem_dec(ss, ct, sk) != 0 ||
     memcmp(ss, expected_ss, ss_len) != 0) {
    fprintf(stderr, "valid control did not reproduce KAT\n");
    return 4;
  }
  if(crypto_kem_dec(ss, bad_c1, sk) != 0 ||
     memcmp(ss, expected_ss, ss_len) == 0) {
    fprintf(stderr, "bad-c1 control did not enter rejection\n");
    return 4;
  }

  for(int i = 0; i < 8; i++) {
    (void)time_decode(ss, ct, sk, 1);
    (void)time_decode(ss, bad_c1, sk, 1);
  }

  const uint64_t start_sigma = g_selected_sigma;
  const uint64_t start_mprime = g_selected_mprime;
  const uint64_t start_calls = g_kdf_calls;

  for(uint32_t i = 0; i < reps; i++) {
    if(rng64() & 1U) {
      valid_ns[i] = time_decode(ss, ct, sk, 1);
      fail_ns[i] = time_decode(ss, bad_c1, sk, 1);
    } else {
      fail_ns[i] = time_decode(ss, bad_c1, sk, 1);
      valid_ns[i] = time_decode(ss, ct, sk, 1);
    }
    ratios[i] = (double)fail_ns[i] / (double)valid_ns[i];
  }

  double sum_log = 0.0, sum_log2 = 0.0;
  for(uint32_t i = 0; i < reps; i++) {
    const double lr = log(ratios[i]);
    sum_log += lr;
    sum_log2 += lr * lr;
  }
  const double mean_log = sum_log / reps;
  const double var_log =
      (sum_log2 - (double)reps * mean_log * mean_log) / (reps - 1);
  const double se_log = sqrt(var_log / reps);
  const double ci_low = exp(mean_log - 1.96 * se_log);
  const double ci_high = exp(mean_log + 1.96 * se_log);

  printf("reps=%u\n", reps);
  printf("parameter_set=%d\n", BIKE_SECURITY_BITS);
  printf("secretkey_bytes=%zu\nciphertext_bytes=%zu\nsharedsecret_bytes=%zu\n",
         CRYPTO_SECRETKEYBYTES, CRYPTO_CIPHERTEXTBYTES, CRYPTO_BYTES);
  printf("branch_count_sigma=%" PRIu64 "\n",
         g_selected_sigma - start_sigma);
  printf("branch_count_mprime=%" PRIu64 "\n",
         g_selected_mprime - start_mprime);
  printf("kdf_calls=%" PRIu64 "\n", g_kdf_calls - start_calls);
  printf("valid_median_thread_ns=%.3f\n", median(valid_ns, reps));
  printf("failure_median_thread_ns=%.3f\n", median(fail_ns, reps));
  printf("paired_geomean_ratio=%.9f\n", exp(mean_log));
  printf("paired_ratio_ci95=[%.9f,%.9f]\n", ci_low, ci_high);
  printf("paired_ratio_ns_estimate=%.3f\n",
         exp(mean_log) *
             ((double)valid_ns[0] + (double)fail_ns[0]) * 0.5 -
         ((double)valid_ns[0] + (double)fail_ns[0]) * 0.5);
  printf("RAW_BEGIN\n");
  printf("trial,valid_thread_ns,failure_thread_ns,ratio\n");
  for(uint32_t i = 0; i < reps; i++) {
    printf("%u,%" PRIu64 ",%" PRIu64 ",%.12f\n",
           i, valid_ns[i], fail_ns[i], ratios[i]);
  }
  return 0;
}
