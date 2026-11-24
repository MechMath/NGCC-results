#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"
#include "parameters.h"

DRNG_ctx drng_algorithm;

static void print_hex(const char *label, const unsigned char *data, size_t len) {
  printf("%s=", label);
  for(size_t i = 0; i < len; i++) {
    printf("%02X", data[i]);
  }
  putchar('\n');
}

static void reseed(const char *label) {
  unsigned char seed[64];
  size_t label_len = strlen(label);
  for(size_t i = 0; i < sizeof(seed); i++) {
    seed[i] = (unsigned char) label[i % label_len];
  }
  init_random_number(&drng_algorithm, seed, sizeof(seed));
}

static int keypair(unsigned char **pk, unsigned char **sk) {
  unsigned long long pk_len = kem_get_pk_len_bytes();
  unsigned long long sk_len = kem_get_sk_len_bytes();
  *pk = calloc((size_t) pk_len, 1);
  *sk = calloc((size_t) sk_len, 1);
  if(*pk == NULL || *sk == NULL) {
    return -1;
  }
  return kem_keygen(*pk, &pk_len, *sk, &sk_len);
}

static int encaps(unsigned char *pk, unsigned char **ss, unsigned char **ct) {
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned long long ct_len = kem_get_ct_len_bytes();
  *ss = calloc((size_t) ss_len, 1);
  *ct = calloc((size_t) ct_len, 1);
  if(*ss == NULL || *ct == NULL) {
    return -1;
  }
  return kem_enc(pk, kem_get_pk_len_bytes(), *ss, &ss_len, *ct, &ct_len);
}

static int decaps(const unsigned char *sk, const unsigned char *ct,
                  unsigned char *ss, unsigned long long sk_len,
                  unsigned long long ct_len) {
  unsigned long long out_len = kem_get_ss_len_bytes();
  return kem_dec((unsigned char *) sk, sk_len, (unsigned char *) ct, ct_len,
                 ss, &out_len);
}

int main(int argc, char **argv) {
  struct timespec started, finished;
  struct rusage usage;
  clock_gettime(CLOCK_MONOTONIC, &started);
  const size_t pk_len = (size_t) kem_get_pk_len_bytes();
  const size_t sk_len = (size_t) kem_get_sk_len_bytes();
  const size_t ct_len = (size_t) kem_get_ct_len_bytes();
  const size_t ss_len = (size_t) kem_get_ss_len_bytes();
  unsigned char *pk = NULL, *sk = NULL, *ss = NULL, *ct = NULL;
  unsigned char *pk2 = NULL, *sk2 = NULL, *ss2 = NULL, *ct2 = NULL;
  unsigned char *got = calloc(ss_len, 1);
  unsigned char *got2 = calloc(ss_len, 1);
  unsigned char *mut = malloc(ct_len);
  int failures = 0;

  printf("profile=%s\n", ALGORITHM_INSTANCE);
  printf("pk_len=%zu\nsk_len=%zu\nct_len=%zu\nss_len=%zu\n",
         pk_len, sk_len, ct_len, ss_len);
  printf("pke_ct_len=%d\nsalt_len=%d\n", CPAPKE_CT_SIZE, PARAMS_SALT_SIZE);

  reseed("determinism-A");
  failures |= keypair(&pk, &sk);
  failures |= encaps(pk, &ss, &ct);
  failures |= decaps(sk, ct, got, sk_len, ct_len);
  printf("positive_match=%d\n", memcmp(ss, got, ss_len) == 0);
  print_hex("pk", pk, pk_len);
  print_hex("sk", sk, sk_len);
  print_hex("ct", ct, ct_len);
  print_hex("ss", ss, ss_len);

  if(argc > 1 && strcmp(argv[1], "short-ct") == 0) {
    unsigned char *short_ct = malloc(1);
    short_ct[0] = ct[0];
    printf("short_ct_probe_begin supplied_len=1\n");
    fflush(stdout);
    failures |= decaps(sk, short_ct, got, sk_len, 1);
    printf("short_ct_probe_returned\n");
    free(short_ct);
    return failures != 0;
  }

  reseed("determinism-A");
  failures |= keypair(&pk2, &sk2);
  failures |= encaps(pk2, &ss2, &ct2);
  printf("same_seed_pk_equal=%d\n", memcmp(pk, pk2, pk_len) == 0);
  printf("same_seed_ct_equal=%d\n", memcmp(ct, ct2, ct_len) == 0);
  printf("same_seed_ss_equal=%d\n", memcmp(ss, ss2, ss_len) == 0);

  reseed("determinism-B");
  free(pk2);
  free(sk2);
  free(ss2);
  free(ct2);
  pk2 = sk2 = ss2 = ct2 = NULL;
  failures |= keypair(&pk2, &sk2);
  failures |= encaps(pk2, &ss2, &ct2);
  printf("different_seed_pk_equal=%d\n", memcmp(pk, pk2, pk_len) == 0);
  printf("different_seed_ct_equal=%d\n", memcmp(ct, ct2, ct_len) == 0);
  printf("different_seed_ss_equal=%d\n", memcmp(ss, ss2, ss_len) == 0);

  memset(got, 0, ss_len);
  failures |= decaps(sk2, ct, got, sk_len, ct_len);
  printf("wrong_sk_matches=%d\n", memcmp(ss, got, ss_len) == 0);

  const size_t positions[] = {
    0, 1, CPAPKE_CT_SIZE / 2, CPAPKE_CT_SIZE - 2, CPAPKE_CT_SIZE - 1,
    CPAPKE_CT_SIZE, CPAPKE_CT_SIZE + 1, ct_len - 1
  };
  const unsigned char masks[] = {0x01, 0x80};
  for(size_t i = 0; i < sizeof(positions) / sizeof(positions[0]); i++) {
    for(size_t j = 0; j < sizeof(masks) / sizeof(masks[0]); j++) {
      memcpy(mut, ct, ct_len);
      mut[positions[i]] ^= masks[j];
      memset(got, 0xA5, ss_len);
      int rc = decaps(sk, mut, got, sk_len, ct_len);
      printf("tamper pos=%zu mask=%02X rc=%d matches_valid=%d secret=",
             positions[i], masks[j], rc, memcmp(ss, got, ss_len) == 0);
      for(size_t k = 0; k < ss_len; k++) {
        printf("%02X", got[k]);
      }
      putchar('\n');
    }
  }

  memset(got, 0, ss_len);
  memset(got2, 0, ss_len);
  failures |= decaps(sk, ct, got, 0, 0);
  failures |= decaps(sk, ct, got2, sk_len, ct_len);
  printf("zero_length_rc=%d zero_length_matches_full=%d\n",
         failures, memcmp(got, got2, ss_len) == 0);

  free(mut);
  free(got2);
  free(got);
  free(ct2);
  free(ss2);
  free(sk2);
  free(pk2);
  free(ct);
  free(ss);
  free(sk);
  free(pk);
  clock_gettime(CLOCK_MONOTONIC, &finished);
  getrusage(RUSAGE_SELF, &usage);
  printf("elapsed_seconds=%.6f\n",
         (double) (finished.tv_sec - started.tv_sec) +
         (double) (finished.tv_nsec - started.tv_nsec) / 1000000000.0);
  printf("max_rss_kib=%ld\n", usage.ru_maxrss);
  return failures != 0;
}
