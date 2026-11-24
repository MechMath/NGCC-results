#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "cleanup.h"
#include "decode.h"
#include "gf2x.h"
#include "kem.h"
#include "rng.h"
#include "sampling.h"
#include "sha.h"
#include "types.h"

static uint64_t fnv64(const void *data, size_t len)
{
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = UINT64_C(1469598103934665603);
  for(size_t i = 0; i < len; i++) {
    h ^= p[i];
    h *= UINT64_C(1099511628211);
  }
  return h;
}

static int accept(const ct_t *ct, const e_t *e)
{
  m_t le = {0};
  m_t mp = {0};
  pad_e_t pe = {0};
  sha_dgst_t dgst = {0};
  e_t hm = {0};
  seed_t seed = {0};

  pe.val[0].val = e->val[0];
  pe.val[1].val = e->val[1];
  if(sha(&dgst, sizeof(e_t), (const uint8_t *)e) != SUCCESS) {
    return -1;
  }
  memcpy(le.raw, dgst.u.raw, sizeof(le.raw));
  for(size_t i = 0; i < sizeof(mp.raw); i++) {
    mp.raw[i] = ct->c1.raw[i] ^ le.raw[i];
  }
  memcpy(seed.raw, mp.raw, sizeof(seed.raw));
  if(generate_error_vector(&pe, &seed) != SUCCESS) {
    return -1;
  }
  hm.val[0] = pe.val[0].val;
  hm.val[1] = pe.val[1].val;
  return memcmp(&hm, e, sizeof(hm)) == 0;
}

static int residual_ok(const ct_t *ct, const sk_t *sk, const e_t *e)
{
  pad_r_t lhs = {0};
  pad_r_t rhs = {0};
  pad_r_t t = {0};
  pad_r_t c0 = {0};
  pad_r_t h0 = {0};
  pad_r_t h1 = {0};
  pad_r_t e0 = {0};
  pad_r_t e1 = {0};

  c0.val = ct->c0;
  h0.val = sk->bin[0];
  h1.val = sk->bin[1];
  e0.val = e->val[0];
  e1.val = e->val[1];

  gf2x_mod_mul(&lhs, &e0, &h0);
  gf2x_mod_mul(&t, &e1, &h1);
  gf2x_mod_add(&lhs, &lhs, &t);
  gf2x_mod_mul(&rhs, &c0, &h0);
  return memcmp(&lhs, &rhs, sizeof(lhs)) == 0;
}

static uint32_t bit_weight(const uint8_t *p, size_t bits)
{
  uint32_t w = 0;
  for(size_t i = 0; i < bits; i++) {
    w += (p[i / 8] >> (i % 8)) & 1U;
  }
  return w;
}

static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);
static uint32_t next_u32(void)
{
  rng_state ^= rng_state << 13;
  rng_state ^= rng_state >> 7;
  rng_state ^= rng_state << 17;
  return (uint32_t)rng_state;
}

int main(int argc, char **argv)
{
  unsigned char entropy[48];
  unsigned char pk_buf[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk_buf[CRYPTO_SECRETKEYBYTES];
  m_t m = {0};
  seed_t seed = {0};
  pad_e_t chosen = {0};
  pad_r_t p_pk = {0};
  pad_r_t p_ct = {0};
  ct_t base = {0};
  ct_t ct;
  e_t e0 = {0};
  e_t e1 = {0};
  e_t chosen_e = {0};
  sha_dgst_t dgst = {0};
  uint32_t cases = (argc > 1) ? (uint32_t)strtoul(argv[1], NULL, 10) : 2000U;
  uint64_t base_hash;
  uint32_t hits = 0, diffs = 0, approx_one = 0;

  for(uint32_t i = 0; i < sizeof(entropy); i++) {
    entropy[i] = (unsigned char)(0x31U + 7U * i);
  }
  randombytes_init(entropy, NULL, 256);
  if(crypto_kem_keypair(pk_buf, sk_buf) != 0) {
    return 2;
  }
  const sk_t *sk = (const sk_t *)sk_buf;

  for(uint32_t i = 0; i < sizeof(m.raw); i++) {
    m.raw[i] = (uint8_t)(0xa5U ^ (uint8_t)(19U * i));
  }
  memcpy(seed.raw, m.raw, sizeof(seed.raw));
  if(generate_error_vector(&chosen, &seed) != SUCCESS) {
    return 3;
  }
  chosen_e.val[0] = chosen.val[0].val;
  chosen_e.val[1] = chosen.val[1].val;

  p_pk.val = sk->pk;
  gf2x_mod_mul(&p_ct, &chosen.val[1], &p_pk);
  gf2x_mod_add(&p_ct, &p_ct, &chosen.val[0]);
  base.c0 = p_ct.val;
  if(sha(&dgst, sizeof(e_t), (const uint8_t *)&chosen_e) != SUCCESS) {
    return 4;
  }
  for(size_t i = 0; i < sizeof(m.raw); i++) {
    base.c1.raw[i] = dgst.u.raw[i] ^ m.raw[i];
  }

  decode(&e0, &base, sk);
  base_hash = fnv64(&e0, sizeof(e0));
  printf("model=%s key_hash=%016" PRIx64 " message_hash=%016" PRIx64
         " chosen=%016" PRIx64 " baseline=%016" PRIx64
         " chosen_fixed=%d chosen_residual=%d baseline_fixed=%d "
         "baseline_residual=%d baseline_equals_chosen=%d cases=%u\n",
         (argc > 2) ? argv[2] : "unknown", fnv64(sk_buf, sizeof(sk_buf)),
         fnv64(m.raw, sizeof(m.raw)), fnv64(&chosen_e, sizeof(chosen_e)),
         base_hash, accept(&base, &chosen_e),
         residual_ok(&base, sk, &chosen_e),
         accept(&base, &e0), residual_ok(&base, sk, &e0),
         memcmp(&e0, &chosen_e, sizeof(e0)) == 0, cases);
  printf("case,bits,delta_hash,residual_ok,guess_hash,guess_weight,"
         "equals_baseline,fixed_point\n");

  for(uint32_t c = 0; c < cases; c++) {
    uint8_t delta[R_BYTES] = {0};
    uint32_t nbits = 1U + (next_u32() % 4U);
    for(uint32_t j = 0; j < nbits; j++) {
      uint32_t bit = next_u32() % R_BITS;
      delta[bit / 8] ^= (uint8_t)(1U << (bit % 8));
    }
    ct = base;
    for(size_t i = 0; i < R_BYTES; i++) {
      ct.c0.raw[i] ^= delta[i];
    }
    decode(&e1, &ct, sk);
    int fp = accept(&ct, &e1);
    int same = memcmp(&e0, &e1, sizeof(e0)) == 0;
    int delta_bits = (int)bit_weight(delta, R_BITS);
    printf("%u,%d,%016" PRIx64 ",%d,%016" PRIx64 ",%u,%d,%d\n",
           c, delta_bits, fnv64(delta, R_BYTES), residual_ok(&ct, sk, &e1),
           fnv64(&e1, sizeof(e1)), bit_weight((const uint8_t *)&e1, N_BITS),
           same, fp);
    diffs += !same;
    hits += fp;
    approx_one += same && fp;
  }
  printf("summary cases=%u guess_differences=%u fixed_points=%u "
         "baseline_preserved_genuine=%u\n", cases, diffs, hits, approx_one);
  return 0;
}
