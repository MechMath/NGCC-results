#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_SHA3
#include "api.h"
#include "owcpa.h"
#include "verify.h"

static void print_hex(const char *label, const uint8_t *p, size_t n)
{
  size_t i;
  printf("%s=", label);
  for (i = 0; i < n; i++) {
    printf("%02x", p[i]);
  }
  putchar('\n');
}

int main(void)
{
  uint8_t *pk = calloc(PK_BYTES, 1);
  uint8_t *sk = calloc(SK_BYTES, 1);
  uint8_t *ct = calloc(CT_BYTES, 1);
  uint8_t *ct_bad = calloc(CT_BYTES, 1);
  uint8_t ss_enc[SEED_BYTES];
  uint8_t ss_dec[SEED_BYTES];
  uint8_t mprime[SEED_BYTES];
  uint8_t hpk[SEED_BYTES];
  uint8_t z[SEED_BYTES];
  uint8_t h2_input[2 * SEED_BYTES];
  uint8_t h2_output[2 * SEED_BYTES];
  uint8_t cprime[CT_BYTES];
  uint8_t reject_input[SEED_BYTES + CT_BYTES];
  uint8_t reject_key[SEED_BYTES];
  const uint8_t *pk_in_sk;
  int fail;

  if (!pk || !sk || !ct || !ct_bad) {
    fprintf(stderr, "allocation failed\n");
    return 2;
  }

  if (mkem_keygen(pk, sk) != 0 || mkem_enc(pk, ss_enc, ct) != 0) {
    fprintf(stderr, "keygen/encapsulation failed\n");
    return 3;
  }

  memset(ss_dec, 0xa5, sizeof(ss_dec));
  if (mkem_dec(sk, ct, ss_dec) != 0) {
    fprintf(stderr, "valid decapsulation failed\n");
    return 4;
  }
  printf("valid_roundtrip_equal=%d\n",
         memcmp(ss_enc, ss_dec, SEED_BYTES) == 0);

  memcpy(ct_bad, ct, CT_BYTES);
  ct_bad[0] ^= 1;
  memset(ss_dec, 0xa5, sizeof(ss_dec));
  if (mkem_dec(sk, ct_bad, ss_dec) != 0) {
    fprintf(stderr, "invalid-ciphertext decapsulation failed\n");
    return 5;
  }

  pk_in_sk = sk + POLYVEC_BYTES;
  owcpa_dec(mprime, ct_bad, sk);
  memcpy(hpk, sk + SK_BYTES - 2 * SEED_BYTES, SEED_BYTES);
  memcpy(z, sk + SK_BYTES - SEED_BYTES, SEED_BYTES);

  memcpy(h2_input, mprime, SEED_BYTES);
  memcpy(h2_input + SEED_BYTES, hpk, SEED_BYTES);
  Hash2(h2_output, h2_input, sizeof(h2_input));

  owcpa_enc(cprime, mprime, pk_in_sk, h2_output + SEED_BYTES);
  fail = verify(ct_bad, cprime, CT_BYTES);

  memcpy(reject_input, z, SEED_BYTES);
  memcpy(reject_input + SEED_BYTES, ct_bad, CT_BYTES);
  KDF(reject_key, SEED_BYTES, reject_input, sizeof(reject_input));

  printf("tampered_reencryption_fail=%d\n", fail);
  printf("returned_equals_acceptance_h2=%d\n",
         memcmp(ss_dec, h2_output, SEED_BYTES) == 0);
  printf("returned_equals_challenge_ss=%d\n",
         memcmp(ss_dec, ss_enc, SEED_BYTES) == 0);
  printf("returned_equals_expected_rejection=%d\n",
         memcmp(ss_dec, reject_key, SEED_BYTES) == 0);
  printf("rejection_differs_from_acceptance=%d\n",
         memcmp(reject_key, h2_output, SEED_BYTES) != 0);
  print_hex("returned_ss", ss_dec, SEED_BYTES);
  print_hex("challenge_ss", ss_enc, SEED_BYTES);
  print_hex("acceptance_key", h2_output, SEED_BYTES);
  print_hex("expected_rejection", reject_key, SEED_BYTES);

  free(ct_bad);
  free(ct);
  free(sk);
  free(pk);
  return (fail == 1 &&
          memcmp(ss_dec, h2_output, SEED_BYTES) == 0 &&
          memcmp(ss_dec, reject_key, SEED_BYTES) != 0) ? 0 : 1;
}
