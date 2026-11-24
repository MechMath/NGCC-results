#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "drng.h"
#include "params.h"

extern DRNG_ctx drng_algorithm;
DRNG_ctx drng_algorithm;

static int verify(const unsigned char *pk,
                  const unsigned char *sn,
                  unsigned long long sn_len,
                  unsigned char *out,
                  unsigned long long out_len)
{
  return sig_verify(pk, CRYPTO_PUBLICKEYBYTES, sn, sn_len, out, out_len);
}

int main(void)
{
  static const unsigned char master_seed[64] = {
    0x41,0x54,0x4c,0x41,0x53,0x2d,0x6d,0x61,0x6c,0x6c,0x65,0x61,0x62,0x69,0x6c,0x69,
    0x74,0x79,0x2d,0x74,0x65,0x73,0x74,0x2d,0x73,0x65,0x65,0x64,0x2d,0x30,0x30,0x30,
    0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,
    0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30
  };
  static const unsigned char msg[] =
    "MORNING-ATLAS local noncanonical-encoding experiment";
  const unsigned long long z_bytes = (unsigned long long)L * POLZ_SIZE_PACKED;
  const unsigned long long hint_bytes = OMEGA + K;
  const unsigned long long c_mask_bytes = N / 8;
  const unsigned long long unused_sign_byte = z_bytes + hint_bytes + c_mask_bytes + 3;
  const unsigned char unused_sign_mask = 0x80; /* sign bit index 31 for KAPPA=31 */
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char sn[CRYPTO_BYTES + sizeof(msg) - 1];
  unsigned char altered[sizeof(sn)];
  unsigned char recovered[sizeof(msg) - 1];
  unsigned long long pk_len = 0;
  unsigned long long sk_len = 0;
  unsigned long long sn_len = 0;
  unsigned int last_hint_boundary;
  unsigned long long padding_offset = 0;
  int keygen_rt;
  int sign_rt;
  int base_verify_rt;
  int base_ok;
  int unused_ok;
  int used_bit_ok;
  int padding_ok;

  if (init_random_number(&drng_algorithm, master_seed, sizeof(master_seed)) != 0) {
    fprintf(stderr, "DRNG initialization failed\n");
    return 2;
  }
  keygen_rt = sig_keygen(pk, &pk_len, sk, &sk_len);
  if (keygen_rt != 0) {
    fprintf(stderr, "key generation failed\n");
    return 2;
  }
  sign_rt = sig_sign(sk, sk_len, msg, sizeof(msg) - 1, sn, &sn_len);
  if (sign_rt != 0) {
    fprintf(stderr, "signing failed\n");
    return 2;
  }

  base_verify_rt = verify(pk, sn, sn_len, recovered, sizeof(msg) - 1);
  base_ok = base_verify_rt == 0;

  memcpy(altered, sn, sizeof(sn));
  altered[unused_sign_byte] ^= unused_sign_mask;
  unused_ok = verify(pk, altered, sn_len, recovered, sizeof(msg) - 1) == 0;

  memcpy(altered, sn, sizeof(sn));
  altered[unused_sign_byte] ^= 0x01; /* first sign bit is used for KAPPA=31 */
  used_bit_ok = verify(pk, altered, sn_len, recovered, sizeof(msg) - 1) == 0;

  last_hint_boundary = sn[z_bytes + OMEGA + K - 1];
  if (last_hint_boundary < OMEGA) {
    padding_offset = z_bytes + last_hint_boundary;
    memcpy(altered, sn, sizeof(sn));
    altered[padding_offset] ^= 0x01;
    padding_ok = verify(pk, altered, sn_len, recovered, sizeof(msg) - 1) == 0;
  } else {
    padding_ok = -1;
  }

  printf("params n=%u k=%u l=%u kappa=%u omega=%u signature=%u message=%zu\n",
         N, K, L, KAPPA, OMEGA, CRYPTO_BYTES, sizeof(msg) - 1);
  printf("keygen_rt=%d sign_rt=%d pk_len=%llu sk_len=%llu sn_len=%llu base_verify_rt=%d\n",
         keygen_rt, sign_rt, pk_len, sk_len, sn_len, base_verify_rt);
  printf("recovered_matches=%d\n",
         memcmp(recovered, msg, sizeof(msg) - 1) == 0);
  printf("offsets z=%llu hint=%llu challenge_mask=%llu unused_sign=%llu\n",
         z_bytes, hint_bytes, c_mask_bytes, unused_sign_byte);
  printf("hint_count=%u padding_offset=%llu\n",
         last_hint_boundary, padding_offset);
  printf("base_verifies=%d unused_sign_flip_verifies=%d used_sign_flip_verifies=%d\n",
         base_ok, unused_ok, used_bit_ok);
  printf("hint_padding_flip_verifies=%d\n", padding_ok);

  if (!base_ok) {
    fprintf(stderr, "positive control failed\n");
    return 3;
  }
  if (!unused_ok || padding_ok == 0 || used_bit_ok) {
    fprintf(stderr, "negative-control or malleability predicate failed\n");
    return 4;
  }
  return 0;
}
