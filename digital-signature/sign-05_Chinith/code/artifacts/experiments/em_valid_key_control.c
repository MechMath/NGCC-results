#include "sm4th_em_d2_128f_loose.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  static const uint8_t sk_key[16] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  };
  static const uint8_t sk_input[16] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  };
  static const uint8_t expected_pk[32] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      0xba, 0xae, 0xfc, 0x08, 0xb3, 0x97, 0xee, 0xec,
      0x0b, 0xd4, 0x88, 0x72, 0x1b, 0xe0, 0xe4, 0x5f,
  };
  static const uint8_t msg[] = "legitimate signing control";
  uint8_t pk[32], sk[32], rho[16] = {0};
  size_t sig_len = sm4th_em_d2_128f_loose_signature_size();
  uint8_t *sig = calloc(1, sig_len);
  if (!sig) {
    return 2;
  }
  int kg = sm4th_em_d2_128f_loose_keygen(pk, sk, sk_key, sk_input);
  int pk_match = memcmp(pk, expected_pk, sizeof(pk)) == 0;
  int sign_rc = sm4th_em_d2_128f_loose_sign_with_randomness(
      sk, msg, sizeof(msg) - 1, rho, sizeof(rho), sig, &sig_len);
  int verify_rc = sm4th_em_d2_128f_loose_verify(
      pk, msg, sizeof(msg) - 1, sig, sig_len);
  static const uint8_t wrong[] = "different message";
  int wrong_msg_rc = sm4th_em_d2_128f_loose_verify(
      pk, wrong, sizeof(wrong) - 1, sig, sig_len);
  printf("keygen_rc=%d pk_match=%d sign_rc=%d verify_rc=%d wrong_msg_rc=%d\n",
         kg, pk_match, sign_rc, verify_rc, wrong_msg_rc);
  free(sig);
  return kg == 0 && pk_match && sign_rc == 0 && verify_rc == 0 &&
                 wrong_msg_rc != 0
             ? 0
             : 1;
}
