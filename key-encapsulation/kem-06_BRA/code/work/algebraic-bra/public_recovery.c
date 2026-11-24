#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "augmented_gabidulin.h"
#include "bra.h"
#include "drng.h"
#include "parameters.h"
#include "parsing.h"
#include "rbc_qre.h"
#include "rbc_vec.h"

DRNG_ctx drng_algorithm;

int main(void) {
  uint8_t pk[BRA_PUBLIC_KEY_BYTES];
  uint8_t sk[BRA_SECRET_KEY_BYTES];
  uint8_t theta[SHA512_BYTES];
  uint64_t word[2] = {1, 0};
  uint8_t drng_seed[64];

  for (uint32_t i = 0; i < sizeof(drng_seed); ++i) {
    drng_seed[i] = (uint8_t)(i * 29u + 11u);
  }
  init_random_number(&drng_algorithm, drng_seed, sizeof(drng_seed));

  rbc_field_init();
  rbc_qre_init_modulus(BRA_PARAM_N);

  rbc_vec m, recovered, codeword;
  rbc_vec_init(&m, BRA_PARAM_K);
  rbc_vec_init(&recovered, BRA_PARAM_K);
  rbc_vec_init(&codeword, BRA_PARAM_N);
  for (uint32_t i = 0; i < BRA_PARAM_K; ++i) {
    word[0] = (uint64_t)i + 1;
    word[1] = 0;
    rbc_elt_set_from_uint64(m[i], word);
  }
  for (uint32_t i = 0; i < SHA512_BYTES; ++i) {
    theta[i] = (uint8_t)(i * 17u + 3u);
  }

  bra_pke_keygen(pk, sk);
  fprintf(stderr, "keygen ok\n");

  rbc_qre u, v;
  rbc_qre_init(&u);
  rbc_qre_init(&v);
  bra_pke_encrypt(u, v, m, theta, pk);
  fprintf(stderr, "encrypt ok\n");

  rbc_qre g, h, s, h_inv, tmp1, tmp2;
  rbc_qre x, y;
  rbc_vec sigma;
  rbc_qre_init(&g);
  rbc_qre_init(&h);
  rbc_qre_init(&s);
  rbc_qre_init(&h_inv);
  rbc_qre_init(&tmp1);
  rbc_qre_init(&tmp2);
  rbc_qre_init(&x);
  rbc_qre_init(&y);
  rbc_vec_init(&sigma, BRA_PARAM_K);
  bra_public_key_from_string(g, h, s, pk);
  bra_secret_key_from_string(x, y, sigma, pk, sk);
  fprintf(stderr, "ranks: g=%u h=%u u=%u\n",
          rbc_vec_get_rank(g->v, BRA_PARAM_N),
          rbc_vec_get_rank(h->v, BRA_PARAM_N),
          rbc_vec_get_rank(u->v, BRA_PARAM_N));

  /* r2 = h^-1 (u-r1), so v - s*h^-1*u = mG + e - s*h^-1*r1. */
  rbc_qre_inv(h_inv, h);
  fprintf(stderr, "h inverse ok\n");
  rbc_qre_mul(tmp1, h, h_inv);
  fprintf(stderr, "rank(h*h^-1)=%u h^-1 rank=%u\n",
          rbc_vec_get_rank(tmp1->v, BRA_PARAM_N),
          rbc_vec_get_rank(h_inv->v, BRA_PARAM_N));
  rbc_qre_mul(tmp1, s, h_inv);
  rbc_qre_mul(tmp2, tmp1, u);
  rbc_qre_add(tmp2, v, tmp2); /* q=2: subtraction equals addition */

  rbc_augmented_gabidulin code;
  rbc_augmented_gabidulin_init(&code, g->v, BRA_PARAM_K, BRA_PARAM_N);
  rbc_augmented_gabidulin_encode(codeword, code, m);
  rbc_vec_add(codeword, tmp2->v, codeword, BRA_PARAM_N);
  uint32_t residual_rank = rbc_vec_get_rank(codeword, BRA_PARAM_N);
  fprintf(stderr, "pre-decode residual rank %u\n", residual_rank);
  rbc_qre_mul(tmp1, u, y);
  rbc_qre_add(tmp1, v, tmp1);
  rbc_augmented_gabidulin_encode(codeword, code, m);
  rbc_vec_add(codeword, tmp1->v, codeword, BRA_PARAM_N);
  fprintf(stderr, "secret residual rank %u\n",
          rbc_vec_get_rank(codeword, BRA_PARAM_N));
  rbc_augmented_gabidulin_decode(recovered, code, tmp2->v);
  fprintf(stderr, "decode ok\n");

  int equal = 1;
  for (uint32_t i = 0; i < BRA_PARAM_K; ++i) {
    equal &= rbc_elt_is_equal_to(m[i], recovered[i]);
  }

  fprintf(stderr, "rank ok\n");

  printf("BRA-%d public plaintext recovery: %s\n",
         BRA_SECURITY, equal ? "PASS" : "FAIL");
  printf("public residual rank: %u (claimed bound <= %u)\n",
         residual_rank, BRA_PARAM_W_e + BRA_PARAM_W_r1);
  return equal ? 0 : 1;
}
