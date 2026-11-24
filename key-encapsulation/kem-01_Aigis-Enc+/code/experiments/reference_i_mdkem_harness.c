#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_SHA3
#include "api.h"

int main(void)
{
  uint8_t *pk = calloc(PK_BYTES, 1);
  uint8_t *sk = calloc(SK_BYTES, 1);
  uint8_t *ct = calloc(CT_BYTES, 1);
  uint8_t ss[SEED_BYTES];
  uint8_t rnd[SEED_BYTES];
  int rc;

  if (!pk || !sk || !ct) {
    fprintf(stderr, "allocation failed\n");
    return 2;
  }

  if (mkem_keygen(pk, sk) != 0) {
    fprintf(stderr, "keygen failed\n");
    return 3;
  }

  memset(rnd, 0x42, sizeof(rnd));
  rc = mdkem_enc(pk, rnd, ss, ct);
  printf("mdkem_enc_rc=%d\n", rc);
  printf("ss=");
  for (size_t i = 0; i < sizeof(ss); i++) {
    printf("%02x", ss[i]);
  }
  putchar('\n');

  free(ct);
  free(sk);
  free(pk);
  return 0;
}
