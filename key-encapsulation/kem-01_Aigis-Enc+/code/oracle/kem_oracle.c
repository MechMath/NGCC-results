/*
 * NON-ORIGINAL ORACLE.
 *
 * This is the original Reference kem.c with exactly one local correction:
 * mdkem_enc reserves 2*SEED_BYTES for kr, as mkem_enc already does. It is used
 * only to establish the intended deterministic output and repeatability.
 */
#include <string.h>

#include "api.h"
#include "params.h"
#include "verify.h"
#include "owcpa.h"
#include "randombytes.h"
#include "hashkdf.h"

int mkem_keygen(uint8_t *pk, uint8_t *sk)
{
  size_t i;
  owcpa_keypair(pk, sk);
  for(i=0;i<PK_BYTES;i++)
    sk[POLYVEC_BYTES + i] = pk[i];
  Hash(sk+SK_BYTES-2*SEED_BYTES,pk,PK_BYTES);
  randombytes(sk + SK_BYTES - SEED_BYTES, SEED_BYTES);
  return 0;
}

int mkem_enc(uint8_t *pk, uint8_t *ss, uint8_t *ct)
{
  uint8_t kr[2*SEED_BYTES];
  uint8_t buf[3*SEED_BYTES];

  randombytes(buf, SEED_BYTES);
  Hash(buf + SEED_BYTES, pk, PK_BYTES);
  Hash2(kr, buf, 2*SEED_BYTES);
  owcpa_enc(ct, buf, pk, kr + SEED_BYTES);
  memcpy(ss, kr, SEED_BYTES);
  return 0;
}

int mdkem_enc(uint8_t *pk, uint8_t *rnd, uint8_t *ss, uint8_t *ct)
{
  uint8_t kr[2*SEED_BYTES]; /* ORACLE CORRECTION */
  uint8_t buf[3 * SEED_BYTES];

  memcpy(buf, rnd, SEED_BYTES);
  Hash(buf + SEED_BYTES, pk, PK_BYTES);
  Hash2(kr, buf, 2*SEED_BYTES);
  owcpa_enc(ct, buf, pk, kr + SEED_BYTES);
  memcpy(ss, kr, SEED_BYTES);
  return 0;
}

int mkem_dec(uint8_t *sk, uint8_t *ct, uint8_t *ss)
{
  size_t i;
  int fail;
  uint8_t cmp[CT_BYTES + 10];
  uint8_t buf[3*SEED_BYTES];
  uint8_t buf2[SEED_BYTES + CT_BYTES];
  uint8_t kr[2*SEED_BYTES];
  const uint8_t *pk = sk + POLYVEC_BYTES;

  owcpa_dec(buf, ct, sk);
  for(i=0;i<SEED_BYTES;i++)
    buf[SEED_BYTES+i] = sk[SK_BYTES-2*SEED_BYTES+i];
  Hash2(kr, buf, 2*SEED_BYTES);
  memcpy(ss,kr,SEED_BYTES);
  owcpa_enc(cmp, buf, pk, kr+SEED_BYTES);
  fail = verify(ct, cmp, CT_BYTES);
  memcpy(buf2, sk-SEED_BYTES, SEED_BYTES);
  memcpy(buf2 + SEED_BYTES, ct, CT_BYTES);
  KDF(buf2, SEED_BYTES, buf2, SEED_BYTES + CT_BYTES);
  cmov(buf, buf2, SEED_BYTES, fail);
  fail = 0;
  return 0;
}
