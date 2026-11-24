#include <stdint.h>
#include <stdio.h>

#include "bra.h"
#include "drng.h"
#include "parameters.h"
#include "rbc_qre.h"
#include "rbc_vspace.h"

DRNG_ctx drng_algorithm;

int main(void) {
  uint8_t pk[BRA_PUBLIC_KEY_BYTES];
  uint8_t sk[BRA_SECRET_KEY_BYTES];
  uint8_t theta[SHA512_BYTES];
  uint8_t seed[64];
  uint64_t word[2] = {1, 0};

  for (uint32_t i = 0; i < sizeof(seed); ++i) {
    seed[i] = (uint8_t)(i * 29u + 11u);
  }
  init_random_number(&drng_algorithm, seed, sizeof(seed));

  rbc_field_init();
  rbc_qre_init_modulus(BRA_PARAM_N);

  rbc_vec m;
  rbc_vec_init(&m, BRA_PARAM_K);
  for (uint32_t i = 0; i < BRA_PARAM_K; ++i) {
    word[0] = (uint64_t)i + 1;
    rbc_elt_set_from_uint64(m[i], word);
  }
  for (uint32_t i = 0; i < SHA512_BYTES; ++i) {
    theta[i] = (uint8_t)(i * 17u + 3u);
  }

  bra_pke_keygen(pk, sk);

  rbc_qre g, h, s, h_inv, u, v, r1, r2, e, tmp;
  rbc_qre_init(&g);
  rbc_qre_init(&h);
  rbc_qre_init(&s);
  rbc_qre_init(&h_inv);
  rbc_qre_init(&u);
  rbc_qre_init(&v);
  rbc_qre_init(&r1);
  rbc_qre_init(&r2);
  rbc_qre_init(&e);
  rbc_qre_init(&tmp);
  bra_public_key_from_string(g, h, s, pk);
  bra_pke_encrypt(u, v, m, theta, pk);

  /*
   * Reproduce the ciphertext randomness from theta exactly as
   * bra_pke_encrypt does, so support ranks can be inspected.
   */
  random_source xof;
  random_source_init(&xof, RANDOM_SOURCE_SEEDEXP);
  random_source_seed_with_len(&xof, theta, SHA512_BYTES);
  rbc_vspace support;
  rbc_vspace_init(
      &support, BRA_PARAM_W_r1 + BRA_PARAM_W_r2 + BRA_PARAM_W_e);
  rbc_vspace_set_random_full_rank(
      &xof, support, BRA_PARAM_W_r1 + BRA_PARAM_W_r2 + BRA_PARAM_W_e);

  rbc_vspace s1, s2, se;
  rbc_vspace_init(&s1, BRA_PARAM_W_r1);
  rbc_vspace_init(&s2, BRA_PARAM_W_r2);
  rbc_vspace_init(&se, BRA_PARAM_W_e);
  for (uint32_t i = 0; i < BRA_PARAM_W_r1; ++i) rbc_elt_set(s1[i], support[i]);
  for (uint32_t i = 0; i < BRA_PARAM_W_r2; ++i) {
    rbc_elt_set(s2[i], support[BRA_PARAM_W_r1 + i]);
  }
  for (uint32_t i = 0; i < BRA_PARAM_W_e; ++i) {
    rbc_elt_set(se[i], support[BRA_PARAM_W_r1 + BRA_PARAM_W_r2 + i]);
  }
  rbc_qre_set_random_from_support(&xof, r1, s1, BRA_PARAM_W_r1, 1);
  rbc_qre_set_random_from_support(&xof, r2, s2, BRA_PARAM_W_r2, 1);
  rbc_qre_set_random_from_support(&xof, e, se, BRA_PARAM_W_e, 1);

  rbc_qre_inv(h_inv, h);
  rbc_qre_mul(tmp, h_inv, r1);
  const uint32_t rank_hinv_r1 = rbc_vec_get_rank(tmp->v, BRA_PARAM_N);
  rbc_qre_mul(tmp, s, tmp);
  const uint32_t rank_s_hinv_r1 = rbc_vec_get_rank(tmp->v, BRA_PARAM_N);

  printf("rank(r1)=%u\n", rbc_vec_get_rank(r1->v, BRA_PARAM_N));
  printf("rank(r2)=%u\n", rbc_vec_get_rank(r2->v, BRA_PARAM_N));
  printf("rank(e)=%u\n", rbc_vec_get_rank(e->v, BRA_PARAM_N));
  printf("rank(h^-1*r1)=%u\n", rank_hinv_r1);
  printf("rank(s*h^-1*r1)=%u\n", rank_s_hinv_r1);
  return 0;
}
