#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef KEM_HEADER
#error "define KEM_HEADER"
#endif
#include KEM_HEADER
#include "drng.h"
#include "parameters.h"

DRNG_ctx drng_algorithm;

static void *xcalloc(size_t n, size_t s) {
  void *p = calloc(n, s);
  if (!p) {
    perror("calloc");
    exit(2);
  }
  return p;
}

static void fill_lcg(unsigned char *p, size_t n, uint64_t seed) {
  size_t i;
  for (i = 0; i < n; i++) {
    seed = seed * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    p[i] = (unsigned char)(seed >> 56);
  }
}

static int make_pattern(unsigned char *ct, size_t n, const char *name) {
  unsigned long seed;
  memset(ct, 0, n);
  if (strcmp(name, "zero") == 0) {
    return 1;
  }
  if (strcmp(name, "ff") == 0) {
    memset(ct, 0xff, n);
    return 1;
  }
  if (sscanf(name, "lcg:%lu", &seed) == 1) {
    fill_lcg(ct, n, (uint64_t)seed);
    return 1;
  }
  if (strcmp(name, "u_zero_v_ff") == 0) {
    memset(ct + BRA_VEC_N_BYTES, 0xff,
           (size_t)BRA_VEC_N_BYTES + BRA_SALT_BYTES);
    return 1;
  }
  if (strcmp(name, "u_ff_v_zero") == 0) {
    memset(ct, 0xff, BRA_VEC_N_BYTES);
    return 1;
  }
  if (strcmp(name, "low_u") == 0) {
    ct[0] = 1;
    return 1;
  }
  if (strcmp(name, "low_v") == 0) {
    ct[BRA_VEC_N_BYTES] = 1;
    return 1;
  }
  if (strcmp(name, "last_byte") == 0) {
    ct[n - 1] = 1;
    return 1;
  }
  if (strcmp(name, "u_last_v_last") == 0) {
    ct[BRA_VEC_N_BYTES - 1] = 1;
    ct[2 * BRA_VEC_N_BYTES - 1] = 1;
    return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  unsigned char nonce[64];
  unsigned long long pk_len = kem_get_pk_len_bytes();
  unsigned long long sk_len = kem_get_sk_len_bytes();
  unsigned long long ct_len = kem_get_ct_len_bytes();
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned char *pk = xcalloc((size_t)pk_len, 1);
  unsigned char *sk = xcalloc((size_t)sk_len, 1);
  unsigned char *ct = xcalloc((size_t)ct_len, 1);
  unsigned char *ss = xcalloc((size_t)ss_len, 1);
  unsigned char *ss_enc = xcalloc((size_t)ss_len, 1);
  unsigned long long out_ss_len = 0;
  int rc;

  if (argc != 2) {
    fprintf(stderr, "usage: %s PATTERN\n", argv[0]);
    return 2;
  }
  memset(nonce, 0x42, sizeof(nonce));
  if (init_random_number(&drng_algorithm, nonce, sizeof(nonce)) != 0 ||
      kem_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
      kem_enc(pk, pk_len, ss_enc, &ss_len, ct, &ct_len) != 0) {
    return 3;
  }
  if (strcmp(argv[1], "canonical") != 0 &&
      !make_pattern(ct, (size_t)ct_len, argv[1])) {
    fprintf(stderr, "unknown pattern: %s\n", argv[1]);
    return 2;
  }

  printf("begin pattern=%s pk=%llu sk=%llu ct=%llu ss=%llu u=%d v=%d salt=%d\n",
         argv[1], pk_len, sk_len, ct_len, ss_len, BRA_VEC_N_BYTES,
         BRA_VEC_N_BYTES, BRA_SALT_BYTES);
  fflush(stdout);
  rc = kem_dec(sk, sk_len, ct, ct_len, ss, &out_ss_len);
  printf("return pattern=%s rc=%d ss_len=%llu equal=%d\n", argv[1], rc,
         out_ss_len, memcmp(ss_enc, ss, (size_t)ss_len) == 0);
  fflush(stdout);

  free(pk);
  free(sk);
  free(ct);
  free(ss);
  free(ss_enc);
  return 0;
}
