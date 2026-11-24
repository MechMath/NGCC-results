#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_BRA-128.h"
#include "drng.h"

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
  for (size_t i = 0; i < n; i++) {
    seed = seed * UINT64_C(6364136223846793005) + UINT64_C(1442695040888963407);
    p[i] = (unsigned char)(seed >> 56);
  }
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

  memset(nonce, 0x42, sizeof(nonce));
  if (init_random_number(&drng_algorithm, nonce, sizeof(nonce)) != 0 ||
      kem_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
      kem_enc(pk, pk_len, ss_enc, &ss_len, ct, &ct_len) != 0) {
    return 3;
  }
  printf("before=canonical exact_pk=%llu exact_sk=%llu exact_ct=%llu\n",
         pk_len, sk_len, ct_len);
  fflush(stdout);
  {
    int canonical_rc = kem_dec(sk, sk_len, ct, ct_len, ss, &out_ss_len);
    printf("case=canonical rc=%d equal=%d\n", canonical_rc,
           memcmp(ss_enc, ss, (size_t)ss_len) == 0);
  }
  fflush(stdout);

  if (!(argc > 1 && strcmp(argv[1], "random1") == 0)) {
    memset(ct, 0, (size_t)ct_len);
    printf("before=zero\n");
    fflush(stdout);
    printf("case=zero rc=%d\n", kem_dec(sk, sk_len, ct, ct_len, ss, &out_ss_len));
    fflush(stdout);

    memset(ct, 0xff, (size_t)ct_len);
    printf("before=ff\n");
    fflush(stdout);
    printf("case=ff rc=%d\n", kem_dec(sk, sk_len, ct, ct_len, ss, &out_ss_len));
    fflush(stdout);
  }

  for (unsigned i = 1; i <= 100; i++) {
    fill_lcg(ct, (size_t)ct_len, i);
    printf("before=random:%u\n", i);
    fflush(stdout);
    int rc = kem_dec(sk, sk_len, ct, ct_len, ss, &out_ss_len);
    printf("case=random:%u rc=%d\n", i, rc);
    fflush(stdout);
  }

  free(pk);
  free(sk);
  free(ct);
  free(ss);
  free(ss_enc);
  return 0;
}
