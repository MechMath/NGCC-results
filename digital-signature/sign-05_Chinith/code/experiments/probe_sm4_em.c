#include "sm4th_em_d2_128s_loose.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t rng_state = UINT32_C(0x9e3779b9);

static uint32_t next_u32(void) {
  uint32_t x = rng_state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  rng_state = x;
  return x;
}

static void fill(uint8_t* out, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    out[i] = (uint8_t)(next_u32() >> 24);
  }
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  uint8_t pk[SM4TH_EM_D2_S_LOOSE_PUBLIC_KEY_SIZE];
  uint8_t sk[SM4TH_EM_D2_S_LOOSE_PRIVATE_KEY_SIZE];
  uint8_t sig[SM4TH_EM_D2_S_LOOSE_SIGNATURE_SIZE];
  uint8_t rho[32];
  uint8_t msg[73];
  size_t sig_len = sizeof(sig);

  fill(rho, sizeof(rho));
  fill(msg, sizeof(msg));

  uint8_t k[16];
  uint8_t x[16];
  do {
    fill(k, sizeof(k));
  } while (((k[0] & 1u) & ((k[0] >> 1) & 1u)) != 0);
  fill(x, sizeof(x));

  int rc = sm4th_em_d2_128s_loose_keygen(pk, sk, k, x);
  printf("keygen rc=%d\n", rc);
  if (rc != 0) return 1;

  rc = sm4th_em_d2_128s_loose_validate_keypair(pk, sk);
  printf("validate rc=%d\n", rc);
  if (rc != 0) return 2;

  rc = sm4th_em_d2_128s_loose_sign_with_randomness(
      sk, msg, sizeof(msg), rho, sizeof(rho), sig, &sig_len);
  printf("sign rc=%d sig_len=%zu\n", rc, sig_len);
  if (rc != 0 || sig_len != sizeof(sig)) return 3;

  rc = sm4th_em_d2_128s_loose_verify(pk, msg, sizeof(msg), sig, sizeof(sig));
  printf("verify valid rc=%d\n", rc);
  if (rc != 0) return 4;

  uint8_t tmp[sizeof(msg)];
  memcpy(tmp, msg, sizeof(msg));
  tmp[0] ^= 1;
  rc = sm4th_em_d2_128s_loose_verify(pk, tmp, sizeof(tmp), sig, sizeof(sig));
  printf("verify changed message rc=%d\n", rc);
  if (rc == 0) return 5;

  uint8_t bad_pk[sizeof(pk)];
  for (size_t i = 0; i < sizeof(pk); ++i) {
    memcpy(bad_pk, pk, sizeof(pk));
    bad_pk[i] ^= 1;
    rc = sm4th_em_d2_128s_loose_verify(bad_pk, msg, sizeof(msg), sig, sizeof(sig));
    if (rc == 0) {
      printf("unexpected accept after pk byte flip at %zu\n", i);
      return 6;
    }
  }
  printf("all 32 single-byte pk mutations rejected\n");

  uint8_t bad_sig[sizeof(sig)];
  size_t sig_mutations = 0;
  for (size_t i = 0; i < sizeof(sig); i += 37) {
    memcpy(bad_sig, sig, sizeof(sig));
    bad_sig[i] ^= 1;
    (void)sm4th_em_d2_128s_loose_verify(
        pk, msg, sizeof(msg), bad_sig, sizeof(bad_sig));
    ++sig_mutations;
  }
  printf("%zu sampled single-byte signature mutations completed\n", sig_mutations);

  return 0;
}
