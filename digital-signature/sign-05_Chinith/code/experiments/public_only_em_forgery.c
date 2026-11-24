#include "sm4th_em_d2_128f_loose.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t target_pk[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0xba, 0xae, 0xfc, 0x08, 0xb3, 0x97, 0xee, 0xec,
    0x0b, 0xd4, 0x88, 0x72, 0x1b, 0xe0, 0xe4, 0x5f,
};

static int forge_and_check(const uint8_t *msg, size_t msg_len, int mutate,
                           const char *save_path) {
  const size_t sig_len = sm4th_em_d2_128f_loose_signature_size();
  uint8_t rho[16] = {0};
  uint8_t witness[128] = {0};
  uint8_t *sig = calloc(1, sig_len);
  if (!sig) {
    return 2;
  }

  sm4th_em_d2_128f_loose_unpacked_private_key_t attacker;
  memset(&attacker, 0, sizeof(attacker));
  memcpy(attacker.owf_input, target_pk, 16);
  memcpy(attacker.owf_output, target_pk + 16, 16);
  attacker.witness = witness;

  size_t out_len = sig_len;
  int sign_rc = sm4th_em_d2_128f_loose_unpacked_sign_with_randomness(
      &attacker, msg, msg_len, rho, sizeof(rho), sig, &out_len);
  if (mutate && out_len > 0) {
    sig[out_len - 1] ^= 1;
  }
  int verify_rc = sm4th_em_d2_128f_loose_verify(target_pk, msg, msg_len, sig, out_len);
  printf("mutate=%d sign_rc=%d verify_rc=%d sig_len=%zu msg=\"%.*s\"\n",
         mutate, sign_rc, verify_rc, out_len, (int)msg_len, msg);
  if (save_path) {
    FILE *f = fopen(save_path, "w");
    if (!f) {
      free(sig);
      return 3;
    }
    fputs("message_hex=", f);
    for (size_t i = 0; i < msg_len; ++i) {
      fprintf(f, "%02x", msg[i]);
    }
    fputc('\n', f);
    fputs("signature_hex=", f);
    for (size_t i = 0; i < out_len; ++i) {
      fprintf(f, "%02x", sig[i]);
    }
    fputc('\n', f);
    fclose(f);
  }
  free(sig);
  return sign_rc == 0 && (mutate ? verify_rc != 0 : verify_rc == 0) ? 0 : 1;
}

int main(void) {
  static const uint8_t msg1[] = "public-key-only forgery for message one";
  static const uint8_t msg2[] = "another arbitrary message";
  int rc = 0;
  rc |= forge_and_check(msg1, sizeof(msg1) - 1, 0,
                        "artifacts/experiments/em_forgery_signature.hex");
  rc |= forge_and_check(msg2, sizeof(msg2) - 1, 0, NULL);
  rc |= forge_and_check(msg1, sizeof(msg1) - 1, 1, NULL);
  printf("target_pk_hex=");
  for (size_t i = 0; i < sizeof(target_pk); ++i) {
    printf("%02x", target_pk[i]);
  }
  putchar('\n');
  return rc;
}
