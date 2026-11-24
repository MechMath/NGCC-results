#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kem.h"

#define MAX_BYTES 32768

static int hex_value(char c)
{
  if(c >= '0' && c <= '9') {
    return c - '0';
  }
  c = (char)toupper((unsigned char)c);
  if(c >= 'A' && c <= 'F') {
    return 10 + c - 'A';
  }
  return -1;
}

static int read_hex_field(FILE *f, const char *field, uint8_t *out, size_t cap,
                          size_t *out_len)
{
  char  *line = NULL;
  size_t line_cap = 0;
  ssize_t n;
  const size_t field_len = strlen(field);

  while((n = getline(&line, &line_cap, f)) >= 0) {
    if((size_t)n > field_len && strncmp(line, field, field_len) == 0) {
      const char *hex = line + field_len;
      size_t hex_len = strcspn(hex, "\r\n");
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

static uint64_t now_ns(void)
{
  struct timespec t;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t);
  return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static uint64_t xorshift64(uint64_t *s)
{
  uint64_t x = *s;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *s = x;
  return x;
}

static int percentage_ge(const char *name, uint64_t value_ns, uint64_t base_ns,
                         uint32_t pct)
{
  return value_ns * 100U >= base_ns * pct;
}

int main(int argc, char **argv)
{
  uint8_t sk[MAX_BYTES] = {0};
  uint8_t ct[MAX_BYTES] = {0};
  uint8_t expected_ss[MAX_BYTES] = {0};
  uint8_t ss[MAX_BYTES] = {0};
  uint8_t bad_c1[MAX_BYTES] = {0};
  uint8_t bad_c0[MAX_BYTES] = {0};
  size_t sk_len = 0;
  size_t ct_len = 0;
  size_t ss_len = 0;
  uint32_t reps = 20000;
  FILE *f;
  uint64_t valid_total = 0;
  uint64_t bad_c1_total = 0;
  uint64_t bad_c0_total = 0;
  double valid_sq = 0.0;
  double bad_c1_sq = 0.0;
  double bad_c0_sq = 0.0;
  uint64_t rng = UINT64_C(0x9e3779b97f4a7c15);
  uint32_t valid_matches = 0;
  uint32_t bad_c1_matches = 0;
  uint32_t bad_c0_matches = 0;

  if(argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s reference-KAT.txt [repetitions]\n", argv[0]);
    return 2;
  }
  if(argc == 3) {
    reps = (uint32_t)strtoul(argv[2], NULL, 10);
  }
  f = fopen(argv[1], "rb");
  if(f == NULL) {
    perror("fopen");
    return 2;
  }
  if(read_hex_field(f, "SK = ", sk, sizeof(sk), &sk_len) != 0 ||
     read_hex_field(f, "CT = ", ct, sizeof(ct), &ct_len) != 0 ||
     read_hex_field(f, "SS = ", expected_ss, sizeof(expected_ss), &ss_len) != 0) {
    fprintf(stderr, "failed to parse first vector\n");
    fclose(f);
    return 2;
  }
  fclose(f);
  if(sk_len != CRYPTO_SECRETKEYBYTES || ct_len != CRYPTO_CIPHERTEXTBYTES ||
     ss_len != CRYPTO_BYTES) {
    fprintf(stderr, "unexpected vector lengths: sk=%zu ct=%zu ss=%zu\n", sk_len,
            ct_len, ss_len);
    return 2;
  }

  memcpy(bad_c1, ct, ct_len);
  bad_c1[ct_len - 1] ^= 1U;

  memcpy(bad_c0, ct, ct_len);
  for(size_t i = 0; i < ct_len - ss_len; i += sizeof(uint64_t)) {
    const uint64_t v = xorshift64(&rng);
    const size_t left = ct_len - ss_len - i;
    memcpy(&bad_c0[i], &v, left < sizeof(v) ? left : sizeof(v));
  }

  (void)crypto_kem_dec(ss, ct, sk);
  (void)crypto_kem_dec(ss, bad_c1, sk);
  (void)crypto_kem_dec(ss, bad_c0, sk);

  for(uint32_t i = 0; i < reps; i++) {
    uint64_t t0;
    uint64_t t1;

    t0 = now_ns();
    (void)crypto_kem_dec(ss, ct, sk);
    t1 = now_ns();
    const uint64_t valid_dt = t1 - t0;
    valid_total += valid_dt;
    valid_sq += (double)valid_dt * (double)valid_dt;
    valid_matches += (memcmp(ss, expected_ss, ss_len) == 0);

    t0 = now_ns();
    (void)crypto_kem_dec(ss, bad_c1, sk);
    t1 = now_ns();
    const uint64_t bad_c1_dt = t1 - t0;
    bad_c1_total += bad_c1_dt;
    bad_c1_sq += (double)bad_c1_dt * (double)bad_c1_dt;
    bad_c1_matches += (memcmp(ss, expected_ss, ss_len) == 0);

    t0 = now_ns();
    (void)crypto_kem_dec(ss, bad_c0, sk);
    t1 = now_ns();
    const uint64_t bad_c0_dt = t1 - t0;
    bad_c0_total += bad_c0_dt;
    bad_c0_sq += (double)bad_c0_dt * (double)bad_c0_dt;
    bad_c0_matches += (memcmp(ss, expected_ss, ss_len) == 0);
  }

  printf("reps=%u\n", reps);
  printf("valid_expected_match=%u\n", valid_matches);
  printf("bad_c1_expected_match=%u\n", bad_c1_matches);
  printf("bad_c0_expected_match=%u\n", bad_c0_matches);
  printf("valid_mean_ns=%.3f\n", (double)valid_total / reps);
  printf("bad_c1_mean_ns=%.3f\n", (double)bad_c1_total / reps);
  printf("bad_c0_mean_ns=%.3f\n", (double)bad_c0_total / reps);
  printf("valid_std_ns=%.3f\n",
         sqrt(valid_sq / reps -
              ((double)valid_total / reps) * ((double)valid_total / reps)));
  printf("bad_c1_std_ns=%.3f\n",
         sqrt(bad_c1_sq / reps -
              ((double)bad_c1_total / reps) * ((double)bad_c1_total / reps)));
  printf("bad_c0_std_ns=%.3f\n",
         sqrt(bad_c0_sq / reps -
              ((double)bad_c0_total / reps) * ((double)bad_c0_total / reps)));
  printf("bad_c1_over_valid=%.6f\n",
         (double)bad_c1_total / (double)valid_total);
  printf("bad_c0_over_valid=%.6f\n",
         (double)bad_c0_total / (double)valid_total);
  printf("bad_c1_ge_110pct=%d\n",
         percentage_ge("bad_c1", bad_c1_total, valid_total, 110));
  printf("bad_c0_ge_110pct=%d\n",
         percentage_ge("bad_c0", bad_c0_total, valid_total, 110));
  return (valid_matches == reps) ? 0 : 1;
}
