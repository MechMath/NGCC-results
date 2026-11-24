#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "drng.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

static int unpack10(const unsigned char *p)
{
  (void)p;
  return 0;
}

int main(void)
{
  static const unsigned char seed[32] = {0};
  static unsigned char m[64] = {0};
  unsigned char pk[RRLWR_SIGN_PK_LEN];
  unsigned char sk[RRLWR_SIGN_SK_LEN];
  unsigned char sn[RRLWR_SIGN_SIG_LEN];
  unsigned char mut[RRLWR_SIGN_SIG_LEN];
  unsigned long long pk_len = sizeof(pk), sk_len = sizeof(sk), sn_len = sizeof(sn);
  unsigned int original_ok, accepted = 0, tested = 0;
  int rc;

  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
    return 2;
  rc = sig_keygen(pk, &pk_len, sk, &sk_len);
  if (rc != 0)
  {
    printf("keygen_rc=%d\n", rc);
    return 3;
  }
  rc = sig_sign(sk, sk_len, m, sizeof(m), sn, &sn_len);
  if (rc != 0)
  {
    printf("sign_rc=%d\n", rc);
    return 4;
  }
  original_ok = (sig_verify(pk, pk_len, sn, sn_len, m, sizeof(m)) == 0);

  printf("pk_len=%llu sk_len=%llu sig_len=%llu original_verify=%u signature_sha_hex=",
         pk_len, sk_len, sn_len, original_ok);
  uint64_t h = UINT64_C(1469598103934665603);
  for (unsigned int i = 0; i < sn_len; i++)
  {
    h ^= sn[i];
    h *= UINT64_C(1099511628211);
  }
  printf("%016llx\n", (unsigned long long)h);

  for (unsigned int bit = 0; bit < 8 * sn_len; bit++)
  {
    memcpy(mut, sn, sn_len);
    mut[bit >> 3] ^= (unsigned char)(1U << (bit & 7));
    tested++;
    if (sig_verify(pk, pk_len, mut, sn_len, m, sizeof(m)) == 0)
    {
      accepted++;
      printf("accepted_bitflip bit=%u byte=%u mask=%02x\n",
             bit, bit >> 3, 1U << (bit & 7));
    }
  }

  memcpy(mut, sn, sn_len);
  mut[0] ^= 1;
  printf("wrong_message_verify=%d\n",
         sig_verify(pk, pk_len, sn, sn_len, mut, sizeof(mut)));
  printf("bad_signature_length_verify=%d\n",
         sig_verify(pk, pk_len, sn, sn_len - 1, m, sizeof(m)));
  printf("bitflips_tested=%u bitflips_accepted=%u\n", tested, accepted);
  return original_ok ? 0 : 5;
}
