#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "params.h"

int main(void)
{
  uint8_t *pk = malloc(PK_BYTES);
  uint8_t *sk = malloc(SK_BYTES);
  uint8_t *rnd = malloc(SEED_BYTES);
  uint8_t *ss = malloc(SEED_BYTES);
  uint8_t *ct = malloc(CT_BYTES);
  if (!pk || !sk || !rnd || !ss || !ct)
    return 2;
  memset(rnd, 0x42, SEED_BYTES);
  if (mkem_keygen(pk, sk) != 0)
    return 3;
  return mdkem_enc(pk, rnd, ss, ct);
}
