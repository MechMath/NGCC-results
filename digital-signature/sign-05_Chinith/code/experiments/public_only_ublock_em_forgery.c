#include "ublockith_em_d3_256f.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  uint8_t sk_key[32];
  uint8_t sk_input[32];
  for (size_t i = 0; i < sizeof(sk_key); ++i) {
    sk_key[i] = (uint8_t)(0x02u + i);
  }
  for (size_t i = 0; i < sizeof(sk_input); ++i) {
    sk_input[i] = (uint8_t)(0x10u + i);
  }

  uint8_t pk[UBLOCKITH_EM_D3_256F_PUBLIC_KEY_SIZE];
  uint8_t sk[UBLOCKITH_EM_D3_256F_PRIVATE_KEY_SIZE];
  if (ublockith_em_d3_256f_keygen(pk, sk, sk_key, sk_input) != 0) {
    return 2;
  }

  static const uint8_t msg[] = "public-key-only uBlockith forgery";
  uint8_t rho[32] = {0};
  uint8_t witness[3072 / 8] = {0};
  size_t sig_len = ublockith_em_d3_256f_signature_size();
  uint8_t *sig = calloc(1, sig_len);
  if (!sig) {
    return 3;
  }

  ublockith_em_d3_256f_unpacked_private_key_t attacker;
  memset(&attacker, 0, sizeof(attacker));
  memcpy(attacker.owf_input, pk, sizeof(attacker.owf_input));
  memcpy(attacker.owf_output, pk + sizeof(attacker.owf_input),
         sizeof(attacker.owf_output));
  attacker.witness = witness;

  int sign_rc = ublockith_em_d3_256f_unpacked_sign_with_randomness(
      &attacker, msg, sizeof(msg) - 1, rho, sizeof(rho), sig, &sig_len);
  int verify_rc = ublockith_em_d3_256f_verify(
      pk, msg, sizeof(msg) - 1, sig, sig_len);

  printf("sign_rc=%d verify_rc=%d sig_len=%zu\n", sign_rc, verify_rc, sig_len);
  printf("pk=");
  for (size_t i = 0; i < sizeof(pk); ++i) {
    printf("%02x", pk[i]);
  }
  putchar('\n');

  if (sig_len > 0) {
    sig[sig_len - 1] ^= 1;
  }
  int negative_rc = ublockith_em_d3_256f_verify(
      pk, msg, sizeof(msg) - 1, sig, sig_len);
  printf("negative_mutation_verify_rc=%d\n", negative_rc);

  free(sig);
  return sign_rc == 0 && verify_rc == 0 && negative_rc != 0 ? 0 : 1;
}
