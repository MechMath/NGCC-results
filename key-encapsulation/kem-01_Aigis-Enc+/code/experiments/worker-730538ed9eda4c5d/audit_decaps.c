#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "hashkdf.h"

#define STRINGIFY_INNER(x) #x
#define STRINGIFY(x) STRINGIFY_INNER(x)

static void print_hex(const char *label, const uint8_t *p, size_t n)
{
  size_t i;

  printf("%s=", label);
  for (i = 0; i < n; ++i) {
    printf("%02x", p[i]);
  }
  putchar('\n');
}

int main(void)
{
  uint8_t *pk = malloc(KEM_PUBLICKEYBYTES);
  uint8_t *sk = malloc(KEM_SECRETKEYBYTES);
  uint8_t *ct = malloc(KEM_CIPHERTEXTBYTES);
  uint8_t *tampered = malloc(KEM_CIPHERTEXTBYTES);
  uint8_t *enc_ss = malloc(KEM_BYTES);
  uint8_t *valid_ss = malloc(KEM_BYTES);
  uint8_t *invalid_ss = malloc(KEM_BYTES);
  uint8_t *expected_reject = malloc(KEM_BYTES);
  uint8_t *reject_input = malloc(KEM_BYTES + KEM_CIPHERTEXTBYTES);
  const uint8_t *z = sk + KEM_SECRETKEYBYTES - KEM_BYTES;
  size_t i;
  size_t bit;
  int tampered_count = 0;
  int incorrect_rejection_count = 0;
  int challenge_key_recovery_count = 0;
  int first_tamper = -1;

  if (!pk || !sk || !ct || !tampered || !enc_ss || !valid_ss ||
      !invalid_ss || !expected_reject || !reject_input) {
    fputs("allocation failure\n", stderr);
    return 2;
  }

  if (mkem_keygen(pk, sk) != 0 ||
      mkem_enc(pk, enc_ss, ct) != 0 ||
      mkem_dec(sk, ct, valid_ss) != 0) {
    fputs("API returned nonzero\n", stderr);
    return 3;
  }

  printf("params=%s public=%d secret=%d ciphertext=%d shared=%d\n",
         STRINGIFY(PARAMS), KEM_PUBLICKEYBYTES, KEM_SECRETKEYBYTES,
         KEM_CIPHERTEXTBYTES, KEM_BYTES);
  printf("valid_encap_decap_equal=%d\n",
         memcmp(enc_ss, valid_ss, KEM_BYTES) == 0);
  print_hex("valid_shared", valid_ss, KEM_BYTES);

  for (i = 0; i < KEM_CIPHERTEXTBYTES; ++i) {
    for (bit = 0; bit < 8; ++bit) {
      memcpy(tampered, ct, KEM_CIPHERTEXTBYTES);
      tampered[i] ^= (uint8_t)(1u << bit);

      memcpy(reject_input, z, KEM_BYTES);
      memcpy(reject_input + KEM_BYTES, tampered, KEM_CIPHERTEXTBYTES);
      KDF(expected_reject, KEM_BYTES, reject_input,
          KEM_BYTES + KEM_CIPHERTEXTBYTES);

      if (mkem_dec(sk, tampered, invalid_ss) != 0) {
        fputs("tampered decapsulation returned nonzero\n", stderr);
        return 4;
      }

      ++tampered_count;
      if (memcmp(invalid_ss, expected_reject, KEM_BYTES) != 0) {
        ++incorrect_rejection_count;
        if (first_tamper < 0) {
          first_tamper = (int)(i * 8 + bit);
          print_hex("first_incorrect_reject", invalid_ss, KEM_BYTES);
          print_hex("first_spec_reject", expected_reject, KEM_BYTES);
        }
      }
      if (memcmp(invalid_ss, valid_ss, KEM_BYTES) == 0) {
        ++challenge_key_recovery_count;
        if (challenge_key_recovery_count == 1) {
          printf("first_challenge_key_recovery_byte=%zu bit=%zu\n", i, bit);
          print_hex("recovered_challenge_shared", invalid_ss, KEM_BYTES);
        }
      }
    }
  }

  printf("tampered_trials=%d\n", tampered_count);
  printf("incorrect_rejection_count=%d\n", incorrect_rejection_count);
  printf("challenge_key_recovery_count=%d\n", challenge_key_recovery_count);
  printf("first_incorrect_tamper_index=%d\n", first_tamper);

  free(reject_input);
  free(expected_reject);
  free(invalid_ss);
  free(valid_ss);
  free(enc_ss);
  free(tampered);
  free(ct);
  free(sk);
  free(pk);

  return (incorrect_rejection_count > 0 &&
          challenge_key_recovery_count > 0) ? 0 : 1;
}
