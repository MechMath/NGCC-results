#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"
#include "hashkdf.h"
#include "owcpa.h"

static const uint8_t *original_ct;

static void print_hex(const char *name, const uint8_t *p, size_t n)
{
  printf("\"%s\":\"", name);
  for (size_t i = 0; i < n; i++)
    printf("%02x", p[i]);
  printf("\"");
}

static void run_case(const char *name, const uint8_t *sk, const uint8_t *ct,
                     const uint8_t *expected_valid, int seq)
{
  uint8_t ss[SEED_BYTES];
  uint8_t expected[SEED_BYTES];
  uint8_t decoded[SEED_BYTES];
  uint8_t decoded_original[SEED_BYTES];
  uint8_t in[SEED_BYTES + CT_BYTES];
  const uint8_t *z = sk + SK_BYTES - SEED_BYTES;

  memset(ss, 0x5a, sizeof ss);
  int rc = mkem_dec((uint8_t *)sk, (uint8_t *)ct, ss);
  memcpy(in, z, SEED_BYTES);
  memcpy(in + SEED_BYTES, ct, CT_BYTES);
  KDF(expected, SEED_BYTES, in, sizeof in);
  owcpa_dec(decoded, ct, sk);
  owcpa_dec(decoded_original, original_ct, sk);

  printf("{\"case\":\"%s\",\"bad_seq\":%d,\"rc\":%d,", name, seq, rc);
  print_hex("returned_ss", ss, sizeof ss);
  printf(",");
  print_hex("expected_H3_s_c", expected, sizeof expected);
  printf(",\"decoded_equals_valid\":%s,\"returned_equals_valid\":%s,\"returned_equals_H3\":%s}\n",
         memcmp(decoded, decoded_original, SEED_BYTES) == 0 ? "true" : "false",
         memcmp(ss, expected_valid, SEED_BYTES) == 0 ? "true" : "false",
         memcmp(ss, expected, SEED_BYTES) == 0 ? "true" : "false");
}

int main(void)
{
  uint8_t *pk = malloc(PK_BYTES);
  uint8_t *sk = malloc(SK_BYTES);
  uint8_t *ct = malloc(CT_BYTES);
  uint8_t *ss_valid = malloc(SEED_BYTES);
  uint8_t *ct_mut = malloc(CT_BYTES);
  if (!pk || !sk || !ct || !ss_valid || !ct_mut)
    return 2;

  printf("{\"params\":{\"PARAMS\":1,\"PK_BYTES\":%d,\"SK_BYTES\":%d,\"CT_BYTES\":%d,\"SS_BYTES\":%d}}\n",
         PK_BYTES, SK_BYTES, CT_BYTES, SEED_BYTES);

  if (mkem_keygen(pk, sk) != 0 || mkem_enc(pk, ss_valid, ct) != 0)
    return 3;
  original_ct = ct;

  run_case("genuine", sk, ct, ss_valid, -1);

  memcpy(ct_mut, ct, CT_BYTES);
  ct_mut[0] ^= 1;
  run_case("flip_first_bit", sk, ct_mut, ss_valid, 0);
  run_case("repeat_flip_first_bit_1", sk, ct_mut, ss_valid, 0);
  run_case("repeat_flip_first_bit_2", sk, ct_mut, ss_valid, 0);

  memcpy(ct_mut, ct, CT_BYTES);
  ct_mut[CT_BYTES - 1] ^= 1;
  run_case("flip_last_bit", sk, ct_mut, ss_valid, 1);

  memset(ct_mut, 0, CT_BYTES);
  run_case("all_zero", sk, ct_mut, ss_valid, 2);

  memset(ct_mut, 0xff, CT_BYTES);
  run_case("all_ff", sk, ct_mut, ss_valid, 3);

  for (size_t i = 0; i < CT_BYTES; i++)
    ct_mut[i] = (uint8_t)(i * 29u + 7u);
  run_case("fixed_structural", sk, ct_mut, ss_valid, 4);

  printf("{\"artifact\":{");
  print_hex("pk", pk, PK_BYTES);
  printf(",");
  print_hex("sk", sk, SK_BYTES);
  printf(",");
  print_hex("valid_ct", ct, CT_BYTES);
  printf(",");
  print_hex("valid_ss", ss_valid, SEED_BYTES);
  printf("}}\n");

  free(pk);
  free(sk);
  free(ct);
  free(ss_valid);
  free(ct_mut);
  return 0;
}
