#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "drng.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"
#include "symmetric.h"

DRNG_ctx drng_algorithm;

static uint32_t next_u32(uint32_t *state) {
  uint32_t x = *state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *state = x;
  return x;
}

#ifdef SPEC_CONFORMING_CHALLENGE
static uint8_t next_xof_byte(uint8_t buf[136], size_t *pos,
                             keccak_state *state) {
  if (*pos == 136) {
    shake256_squeezeblocks(buf, 1, state);
    *pos = 0;
  }
  return buf[(*pos)++];
}

static void conforming_sample_in_ball(poly *c,
                                      const uint8_t seed[CTILDEBYTES]) {
  uint8_t buf[136];
  size_t pos = 136;
  keccak_state state;
  unsigned i, j, s;

  shake256_init(&state);
  shake256_absorb(&state, seed, CTILDEBYTES);
  shake256_finalize(&state);

  for (i = 0; i < N; ++i)
    c->coeffs[i] = 0;

  for (i = N - TAU; i < N; ++i) {
    do {
      j = next_xof_byte(buf, &pos, &state);
      j |= (unsigned)next_xof_byte(buf, &pos, &state) << 8;
    } while (j > i);
    s = next_xof_byte(buf, &pos, &state) & 1;
    c->coeffs[i] = c->coeffs[j];
    c->coeffs[j] = 1 - 2 * (int)s;
  }
}
#endif

static void add_decomp_offset(polyveck *t1) {
  unsigned i, j;
  for (i = 0; i < K; ++i)
    for (j = 0; j < N; ++j)
      t1->vec[i].coeffs[j] += 1 << (D - 1);
}

/*
 * Direct transcription of the original Algorithm 3.  The surrounding
 * implementation conventions (context encoding and DRNG) are held fixed so
 * that the only functional change from the shipped verifier is the required
 * coefficientwise Decomp_d(t1) term.
 */
static unsigned spec_verify_internal(const uint8_t *sig,
                                     size_t siglen,
                                     const uint8_t *m,
                                     size_t mlen,
                                     const uint8_t *pre,
                                     size_t prelen,
                                     const uint8_t *pk) {
  uint8_t buf[K * POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t c[CTILDEBYTES];
  uint8_t c2[CTILDEBYTES];
  poly cp;
  polyvecl mat[K], z, z_ntt;
  polyveck t1, w1, w0;
  keccak_state state;
  unsigned i;

  if (siglen != CRYPTO_BYTES)
    return 1;

  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, sig))
    return 1;

  if (polyvecl_chknorm(&z, GAMMA1 - BETA_Z))
    return 2;

  shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  shake256_init(&state);
  shake256_absorb(&state, mu, TRBYTES);
  shake256_absorb(&state, pre, prelen);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef SPEC_CONFORMING_CHALLENGE
  conforming_sample_in_ball(&cp, c);
#else
  poly_challenge(&cp, c);
#endif
  poly_ntt(&cp);

  polyvec_matrix_expand(mat, rho);
  z_ntt = z;
  polyvecl_ntt(&z_ntt);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z_ntt);

  /* Spec Algorithm 3: c' * (t1 * 2^d + 2^(d-1)). */
  polyveck_shiftl(&t1);
#ifndef SPEC_OMIT_DECOMP
  add_decomp_offset(&t1);
#endif
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);

  polyveck_pack_w1(buf, &w1);
  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, buf, K * POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(c2, CTILDEBYTES, &state);

  for (i = 0; i < CTILDEBYTES; ++i)
    if (c[i] != c2[i])
      return 8;

  if (polyvec_check_L2_bound(&z, &w0))
    return 16;

  return 0;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
  FILE *f = fopen(path, "wb");
  if (f == NULL)
    return -1;
  if (fwrite(buf, 1, len, f) != len) {
    fclose(f);
    return -1;
  }
  return fclose(f);
}

int main(int argc, char **argv) {
  uint32_t seed_value = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 1;
  unsigned trials = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 1000;
  const char *outdir = argc > 3 ? argv[3] : "evidence";
  uint8_t seed_material[64];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  uint8_t msg[256];
  uint8_t rnd[RNDBYTES];
  uint8_t pre[2] = {0, 0};
  size_t siglen;
  uint32_t state;
  unsigned i;
  unsigned actual_reject = 0;
  unsigned spec_reject = 0;
  unsigned spec_hash = 0;
  unsigned spec_znorm = 0;
  unsigned spec_l2 = 0;
  int first_failure = -1;
  int first_actual = -1;
  unsigned first_spec = 0;

  memset(rnd, 0, sizeof(rnd));
  state = seed_value * 0x9e3779b9u + 0x85ebca6bu;
  for (i = 0; i < sizeof(seed_material); ++i)
    seed_material[i] = (uint8_t)(next_u32(&state) >> 24);

  if (init_random_number(&drng_algorithm, seed_material, sizeof(seed_material))) {
    fprintf(stderr, "DRNG initialization failed\n");
    return 2;
  }
  if (crypto_sign_keypair(pk, sk)) {
    fprintf(stderr, "key generation failed\n");
    return 2;
  }

  mkdir(outdir, 0755);

  for (i = 0; i < trials; ++i) {
    unsigned j;
    unsigned spec;
    int actual;

    for (j = 0; j < sizeof(msg); ++j)
      msg[j] = (uint8_t)(next_u32(&state) >> 24);

    siglen = 0;
    crypto_sign_signature_internal(sig, &siglen, msg, sizeof(msg), pre,
                                   sizeof(pre), rnd, sk);
    actual = crypto_sign_verify_internal(sig, CRYPTO_BYTES, msg, sizeof(msg),
                                         pre, sizeof(pre), pk);
    spec = spec_verify_internal(sig, CRYPTO_BYTES, msg, sizeof(msg),
                                pre, sizeof(pre), pk);

    if (actual != 0)
      ++actual_reject;
    if (spec != 0) {
      ++spec_reject;
      if (spec & 8)
        ++spec_hash;
      if (spec & 2)
        ++spec_znorm;
      if (spec & 16)
        ++spec_l2;

      if (first_failure < 0) {
        char path[512];
        first_failure = (int)i;
        first_actual = actual;
        first_spec = spec;
        snprintf(path, sizeof(path), "%s/message.bin", outdir);
        write_file(path, msg, sizeof(msg));
        snprintf(path, sizeof(path), "%s/public_key.bin", outdir);
        write_file(path, pk, sizeof(pk));
        snprintf(path, sizeof(path), "%s/signature.bin", outdir);
        write_file(path, sig, sizeof(sig));
      }
    }
  }

  printf("mode=%d seed=%u trials=%u conforming_sampler=%d omit_decomp=%d "
         "first_failure=%d first_actual=%d "
         "first_spec=%u actual_reject=%u spec_reject=%u spec_znorm=%u "
         "spec_hash=%u spec_l2=%u\n",
         COMPASS_SIG_MODE, seed_value, trials,
#ifdef SPEC_CONFORMING_CHALLENGE
         1,
#else
         0,
#endif
#ifdef SPEC_OMIT_DECOMP
         1,
#else
         0,
#endif
         first_failure, first_actual, first_spec, actual_reject, spec_reject,
         spec_znorm, spec_hash, spec_l2);

  return actual_reject == 0 && spec_hash > 0 ? 0 : 1;
}
