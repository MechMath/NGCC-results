#include "KEM_BRA-128.h"
#include "drng.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

DRNG_ctx drng_algorithm;

static void write_file(const char *path, const unsigned char *data,
                       unsigned long long len) {
  FILE *f = fopen(path, "wb");
  if (!f || fwrite(data, 1, len, f) != len || fclose(f) != 0) {
    perror(path);
    exit(2);
  }
}

int main(int argc, char **argv) {
  if (argc != 2) {
    return 2;
  }

  /*
   * Exact fallback from main_bra.c after fopen("/dev/urandom", "r")
   * returns NULL.
   */
  unsigned char nonce[64];
  memset(nonce, 0x42, sizeof(nonce));
  init_random_number(&drng_algorithm, nonce, sizeof(nonce));

  unsigned long long pk_len = kem_get_pk_len_bytes();
  unsigned long long sk_len = kem_get_sk_len_bytes();
  unsigned long long ct_len = kem_get_ct_len_bytes();
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned long long ss_len2 = 0;
  unsigned char *pk = calloc(pk_len, 1);
  unsigned char *sk = calloc(sk_len, 1);
  unsigned char *ct = calloc(ct_len, 1);
  unsigned char *ss = calloc(ss_len, 1);
  unsigned char *ss2 = calloc(ss_len, 1);
  char path[512];

  if (!pk || !sk || !ct || !ss || !ss2 ||
      kem_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
      kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len) != 0 ||
      kem_dec(sk, sk_len, ct, ct_len, ss2, &ss_len2) != 0 ||
      ss_len2 != ss_len || memcmp(ss, ss2, ss_len) != 0) {
    return 3;
  }

  snprintf(path, sizeof(path), "%s.pk", argv[1]);
  write_file(path, pk, pk_len);
  snprintf(path, sizeof(path), "%s.sk", argv[1]);
  write_file(path, sk, sk_len);
  snprintf(path, sizeof(path), "%s.ct", argv[1]);
  write_file(path, ct, ct_len);
  snprintf(path, sizeof(path), "%s.ss", argv[1]);
  write_file(path, ss, ss_len);

  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    printf("max_rss_kib=%ld\n", usage.ru_maxrss);
  }

  free(pk);
  free(sk);
  free(ct);
  free(ss);
  free(ss2);
  return 0;
}
