#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "parameters.h"
#include "bra.h"
#include "drng.h"
#include "parsing.h"
#include "augmented_gabidulin.h"
#include "rbc_qre.h"
#include "rbc_vspace.h"

DRNG_ctx drng_algorithm;

static int vec_equal(const rbc_vec a, const rbc_vec b, uint32_t n) {
  for (uint32_t i = 0; i < n; i++) {
    if (!rbc_elt_is_equal_to(a[i], b[i])) return 0;
  }
  return 1;
}

static unsigned gf2_rank(const rbc_vec v, uint32_t n) {
  uint64_t basis[67][2] = {{0}};
  unsigned rank = 0;
  for (uint32_t i = 0; i < n; i++) {
    uint64_t row[2] = {v[i][0], v[i][1]};
    for (int bit = 66; bit >= 0; bit--) {
      unsigned word = (unsigned)bit >> 6;
      unsigned off = (unsigned)bit & 63u;
      if (!((row[word] >> off) & 1u)) continue;
      if (!basis[bit][0] && !basis[bit][1]) {
        basis[bit][0] = row[0];
        basis[bit][1] = row[1];
        rank++;
        break;
      }
      row[0] ^= basis[bit][0];
      row[1] ^= basis[bit][1];
    }
  }
  return rank;
}

int main(void) {
  uint8_t pk[BRA_PUBLIC_KEY_BYTES] = {0};
  uint8_t sk[BRA_SECRET_KEY_BYTES] = {0};
  uint8_t theta[64] = {0};
  int ok_count = 0;
  int decode_count = 0;
  uint8_t drng_seed[64];
  memset(drng_seed, 0x5a, sizeof(drng_seed));
  init_random_number(&drng_algorithm, drng_seed, sizeof(drng_seed));

  for (unsigned trial = 0; trial < 16; trial++) {
    bra_pke_keygen(pk, sk);

    random_source rng;
    random_source_init(&rng, RANDOM_SOURCE_PRNG);
    rbc_vec m, m_dec, m_pub;
    rbc_qre g, h, s, h_inv, u, v, w, tmp;
    rbc_qre x, y, r1, r2, e, check, p1, p2, p3, encoded, one;
    rbc_augmented_gabidulin code;
    rbc_vec sigma;
    rbc_vspace sx, sy, sr1, sr2, se, sre;

    rbc_field_init();
    rbc_qre_init_modulus(BRA_PARAM_N);
    rbc_vec_init(&m, BRA_PARAM_K);
    rbc_vec_init(&m_dec, BRA_PARAM_K);
    rbc_vec_init(&m_pub, BRA_PARAM_K);
    rbc_qre_init(&g);
    rbc_qre_init(&h);
    rbc_qre_init(&s);
    rbc_qre_init(&h_inv);
    rbc_qre_init(&u);
    rbc_qre_init(&v);
    rbc_qre_init(&w);
    rbc_qre_init(&tmp);
    rbc_qre_init(&x);
    rbc_qre_init(&y);
    rbc_qre_init(&r1);
    rbc_qre_init(&r2);
    rbc_qre_init(&e);
    rbc_qre_init(&check);
    rbc_qre_init(&p1);
    rbc_qre_init(&p2);
    rbc_qre_init(&p3);
    rbc_qre_init(&encoded);
    rbc_qre_init(&one);
    rbc_vec_init(&sigma, BRA_PARAM_K);
    rbc_vspace_init(&sx, BRA_PARAM_W_x);
    rbc_vspace_init(&sy, BRA_PARAM_W_y);
    rbc_vspace_init(&sr1, BRA_PARAM_W_r1);
    rbc_vspace_init(&sr2, BRA_PARAM_W_r2);
    rbc_vspace_init(&se, BRA_PARAM_W_e);
    rbc_vspace_init(&sre, BRA_PARAM_W_r1 + BRA_PARAM_W_r2 + BRA_PARAM_W_e);

    rbc_vec_set_random(&rng, m, BRA_PARAM_K);
    memset(theta, 0, sizeof(theta));
    theta[0] = (uint8_t)trial;
    bra_pke_encrypt(u, v, m, theta, pk);
    bra_pke_decrypt(m_dec, u, v, sk);

    bra_public_key_from_string(g, h, s, pk);
    bra_secret_key_from_string(x, y, sigma, pk, sk);
    rbc_qre_inv(h_inv, h);

    random_source enc_rng;
    random_source_init(&enc_rng, RANDOM_SOURCE_SEEDEXP);
    random_source_seed_with_len(&enc_rng, theta, SHA512_BYTES);
    rbc_vspace_set_random_full_rank(&enc_rng, sre,
                                    BRA_PARAM_W_r1 + BRA_PARAM_W_r2 + BRA_PARAM_W_e);
    for (uint32_t i = 0; i < BRA_PARAM_W_r1; i++) rbc_elt_set(sr1[i], sre[i]);
    for (uint32_t i = 0; i < BRA_PARAM_W_r2; i++) {
      rbc_elt_set(sr2[i], sre[BRA_PARAM_W_r1 + i]);
    }
    for (uint32_t i = 0; i < BRA_PARAM_W_e; i++) {
      rbc_elt_set(se[i], sre[BRA_PARAM_W_r1 + BRA_PARAM_W_r2 + i]);
    }
    rbc_qre_set_random_from_support(&enc_rng, r1, sr1, BRA_PARAM_W_r1, 1);
    rbc_qre_set_random_from_support(&enc_rng, r2, sr2, BRA_PARAM_W_r2, 1);
    rbc_qre_set_random_from_support(&enc_rng, e, se, BRA_PARAM_W_e, 1);

    /* Public cancellation in characteristic two:
       w = v - s*h^{-1}*u = v + s*h^{-1}*u. */
    rbc_qre_mul(tmp, h_inv, u);
    rbc_qre_mul(w, s, tmp);
    rbc_qre_add(w, w, v);
    rbc_qre_set_monomial(one, 0);
    rbc_qre_mul(p3, h, h_inv);
    int hinv_ok = rbc_qre_is_equal_to(p3, one);

    int control_ok = vec_equal(m, m_dec, BRA_PARAM_K);
    ok_count += control_ok;

    rbc_qre_mul(p1, h_inv, r1);
    rbc_qre_mul(p2, x, p1);
    rbc_qre_mul(p3, y, r1);
    rbc_qre_add(check, p2, p3);
    rbc_qre_add(check, check, e);
    rbc_augmented_gabidulin_init(&code, g->v, BRA_PARAM_K, BRA_PARAM_N);
    rbc_augmented_gabidulin_encode(encoded->v, code, m);
    rbc_qre_add(check, check, encoded);

    printf("trial=%u control=%d rank_w=%u rank_u=%u rank_hinv_u=%u "
           "rank_x=%u rank_y=%u rank_r1=%u rank_r2=%u rank_e=%u "
           "rank_hinv=%u hinv_ok=%d rank_hinv_r1=%u/%u "
           "rank_x_hinv_r1=%u/%u rank_y_r1=%u/%u rank_check=%u/%u\n",
           trial, control_ok,
           rbc_vec_get_rank(w->v, BRA_PARAM_N),
           rbc_vec_get_rank(u->v, BRA_PARAM_N),
           rbc_vec_get_rank(p1->v, BRA_PARAM_N),
           rbc_vec_get_rank(x->v, BRA_PARAM_N),
           rbc_vec_get_rank(y->v, BRA_PARAM_N),
           rbc_vec_get_rank(r1->v, BRA_PARAM_N),
           rbc_vec_get_rank(r2->v, BRA_PARAM_N),
           rbc_vec_get_rank(e->v, BRA_PARAM_N),
           rbc_vec_get_rank(h_inv->v, BRA_PARAM_N),
           hinv_ok,
           rbc_vec_get_rank(p1->v, BRA_PARAM_N),
           gf2_rank(p1->v, BRA_PARAM_N),
           rbc_vec_get_rank(p2->v, BRA_PARAM_N),
           gf2_rank(p2->v, BRA_PARAM_N),
           rbc_vec_get_rank(p3->v, BRA_PARAM_N),
           gf2_rank(p3->v, BRA_PARAM_N),
           rbc_vec_get_rank(check->v, BRA_PARAM_N),
           gf2_rank(check->v, BRA_PARAM_N));
    fflush(stdout);

    int public_ok = 0;
    unsigned rank_w = rbc_vec_get_rank(w->v, BRA_PARAM_N);
    if (hinv_ok && rank_w <= 53) {
      rbc_augmented_gabidulin_decode(m_pub, code, w->v);
      public_ok = vec_equal(m, m_pub, BRA_PARAM_K);
    }
    decode_count += public_ok;
    printf("trial=%u public=%d\n", trial, public_ok);
    fflush(stdout);

    rbc_vec_clear(m);
    rbc_vec_clear(m_dec);
    rbc_vec_clear(m_pub);
    rbc_qre_clear(g);
    rbc_qre_clear(h);
    rbc_qre_clear(s);
    rbc_qre_clear(h_inv);
    rbc_qre_clear(u);
    rbc_qre_clear(v);
    rbc_qre_clear(w);
    rbc_qre_clear(tmp);
    rbc_qre_clear(x);
    rbc_qre_clear(y);
    rbc_qre_clear(r1);
    rbc_qre_clear(r2);
    rbc_qre_clear(e);
    rbc_qre_clear(check);
    rbc_qre_clear(p1);
    rbc_qre_clear(p2);
    rbc_qre_clear(p3);
    rbc_qre_clear(encoded);
    rbc_qre_clear(one);
    rbc_vec_clear(sigma);
    rbc_vspace_clear(sx);
    rbc_vspace_clear(sy);
    rbc_vspace_clear(sr1);
    rbc_vspace_clear(sr2);
    rbc_vspace_clear(se);
    rbc_vspace_clear(sre);
    rbc_qre_clear_modulus();
    random_source_clear(&rng);
    random_source_clear(&enc_rng);
  }

  printf("summary control=%d/%d public=%d/%d\n",
         ok_count, 16, decode_count, 16);
  return ok_count == 16 ? 0 : 2;
}
