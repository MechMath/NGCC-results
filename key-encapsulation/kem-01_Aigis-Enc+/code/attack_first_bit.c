#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "hashkdf.h"
#include "owcpa.h"
#include "verify.h"

int main(int argc, char **argv)
{
  const int trials = argc == 2 ? atoi(argv[1]) : 128;
  uint8_t *pk = malloc(KEM_PUBLICKEYBYTES);
  uint8_t *sk = malloc(KEM_SECRETKEYBYTES);
  uint8_t *ct = malloc(KEM_CIPHERTEXTBYTES);
  uint8_t *tampered = malloc(KEM_CIPHERTEXTBYTES);
  uint8_t *reenc = malloc(KEM_CIPHERTEXTBYTES + 10);
  uint8_t *challenge_ss = malloc(KEM_BYTES);
  uint8_t *attacker_ss = malloc(KEM_BYTES);
  uint8_t *pre_k = malloc(3 * KEM_BYTES);
  uint8_t *kr = malloc(2 * KEM_BYTES);
  int valid_controls = 0;
  int invalid_triggers = 0;
  int recovered = 0;
  int i;

  if (!pk || !sk || !ct || !tampered || !reenc || !challenge_ss ||
      !attacker_ss || !pre_k || !kr || trials < 1) {
    return 2;
  }

  for (i = 0; i < trials; ++i) {
    if (mkem_keygen(pk, sk) != 0 || mkem_enc(pk, challenge_ss, ct) != 0 ||
        mkem_dec(sk, ct, attacker_ss) != 0) {
      return 3;
    }
    if (memcmp(challenge_ss, attacker_ss, KEM_BYTES) == 0) {
      ++valid_controls;
    }

    memcpy(tampered, ct, KEM_CIPHERTEXTBYTES);
    tampered[0] ^= 1;

    owcpa_dec(pre_k, tampered, sk);
    memcpy(pre_k + KEM_BYTES, sk + KEM_SECRETKEYBYTES - 2 * KEM_BYTES,
           KEM_BYTES);
    Hash2(kr, pre_k, 2 * KEM_BYTES);
    owcpa_enc(reenc, pre_k, sk + POLYVEC_BYTES, kr + KEM_BYTES);
    if (verify(tampered, reenc, KEM_CIPHERTEXTBYTES) != 0) {
      ++invalid_triggers;
    }

    if (mkem_dec(sk, tampered, attacker_ss) != 0) {
      return 4;
    }
    if (memcmp(challenge_ss, attacker_ss, KEM_BYTES) == 0) {
      ++recovered;
    }
  }

  printf("trials=%d\n", trials);
  printf("valid_controls=%d\n", valid_controls);
  printf("modified_ciphertext_reencryption_failures=%d\n", invalid_triggers);
  printf("challenge_key_recoveries=%d\n", recovered);

  free(kr);
  free(pre_k);
  free(attacker_ss);
  free(challenge_ss);
  free(reenc);
  free(tampered);
  free(ct);
  free(sk);
  free(pk);
  return (valid_controls == trials && invalid_triggers == trials &&
          recovered == trials) ? 0 : 1;
}
