#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "bra.h"
#include "drng.h"
#include "KEM_BRA-128.h"
#include "parameters.h"
#include "parsing.h"
#include "rbc_qre.h"
#include "rbc_vec.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv) {
  uint8_t seed[64];
  uint8_t pk[BRA_PUBLIC_KEY_BYTES];
  uint8_t sk[BRA_SECRET_KEY_BYTES];
  uint8_t ct[BRA_CIPHERTEXT_BYTES];
  uint8_t ss[BRA_SHARED_SECRET_BYTES];

  for (uint32_t i = 0; i < sizeof(seed); ++i) {
    seed[i] = (uint8_t)(i * 29u + 11u);
  }
  init_random_number(&drng_algorithm, seed, sizeof(seed));

  unsigned long long pk_len = BRA_PUBLIC_KEY_BYTES;
  unsigned long long sk_len = BRA_SECRET_KEY_BYTES;
  unsigned long long ct_len = BRA_CIPHERTEXT_BYTES;
  unsigned long long ss_len = BRA_SHARED_SECRET_BYTES;
  kem_keygen(pk, &pk_len, sk, &sk_len);
  kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);

  if (argc > 1 && strcmp(argv[1], "zero-u") == 0) {
    memset(ct, 0, BRA_VEC_N_BYTES);
  } else if (argc > 1 && strcmp(argv[1], "zero-ct") == 0) {
    memset(ct, 0, BRA_CIPHERTEXT_BYTES);
  } else if (argc > 1 && strcmp(argv[1], "zero-uv") == 0) {
    memset(ct, 0, 2 * BRA_VEC_N_BYTES);
  }

  sk_len = BRA_SECRET_KEY_BYTES;
  ct_len = BRA_CIPHERTEXT_BYTES;
  ss_len = BRA_SHARED_SECRET_BYTES;
  fprintf(stderr, "calling kem_dec\n");
  fflush(stderr);
  kem_dec(sk, sk_len, ct, ct_len, ss, &ss_len);
  fprintf(stderr, "returned from kem_dec\n");
  return 0;
}
