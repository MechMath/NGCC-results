#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "auxfunc.h"
#include "drng.h"
#include "params.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"

DRNG_ctx drng_algorithm;

static int read_file(const char *path, void *data, size_t len) {
  FILE *f = fopen(path, "rb");
  if (!f) {
    perror(path);
    return 1;
  }
  size_t got = fread(data, 1, len, f);
  int extra = fgetc(f);
  fclose(f);
  if (got != len || extra != EOF) {
    fprintf(stderr, "%s: expected exactly %zu bytes, read %zu\n",
            path, len, got);
    return 1;
  }
  return 0;
}

static int32_t center_q(int64_t v) {
  v %= Q;
  if (v < 0) v += Q;
  return (int32_t)(v <= (Q - 1) / 2 ? v : v - Q);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: forge_recovered_key ARTIFACT_DIR\n");
    return 2;
  }
  char path[1024];
  unsigned char *pk = calloc(1, sig_get_pk_len_bytes());
  unsigned char *recovered_sk = calloc(1, sig_get_sk_len_bytes());
  unsigned char *forged_sig = calloc(1, sig_get_sn_len_bytes());
  unsigned char seed[64];
  unsigned char msg[64];
  unsigned long long pk_len, sk_len;

  if (!pk || !recovered_sk || !forged_sig) return 3;
  snprintf(path, sizeof(path), "%s/publickey.bin", argv[1]);
  if (read_file(path, pk, sig_get_pk_len_bytes())) return 4;
  pk_len = sig_get_pk_len_bytes();
  sk_len = sig_get_sk_len_bytes();

  uint8_t rho[SEEDBYTES], tr[CRHBYTES];
  polyvecl s1_rec, s1_hat;
  polyveck t1, t0_rec, s2_rec, as1;
  unpack_pk(rho, &t1, pk);
  if (pseudohash(CRHBYTES * 8, pk, pk_len * 8, tr) != 0) return 4;

  for (int i = 0; i < L; i++) {
    snprintf(path, sizeof(path), "%s/recovered_s1_%d.i32", argv[1], i);
    if (read_file(path, s1_rec.vec[i].coeffs, N * sizeof(int32_t))) return 5;
  }

  polyvecl mat[K];
  s1_hat = s1_rec;
  polyvecl_ntt(&s1_hat);
  polyvec_matrix_expand(mat, rho);
  polyvec_matrix_pointwise_montgomery(&as1, mat, &s1_hat);
  polyveck_reduce(&as1);
  polyveck_invntt_tomont(&as1);
  polyveck_caddq(&as1);
  polyveck_shiftl(&t1);

  unsigned int ambiguous = 0;
  for (int i = 0; i < K; i++) {
    for (int j = 0; j < N; j++) {
      int32_t base = center_q((int64_t)as1.vec[i].coeffs[j] -
                              t1.vec[i].coeffs[j]);
      int found = 0;
      for (int candidate = -ETA; candidate <= ETA; candidate++) {
        int32_t low = center_q((int64_t)base + candidate);
        if (low >= -4096 && low <= 4095) {
          s2_rec.vec[i].coeffs[j] = candidate;
          t0_rec.vec[i].coeffs[j] = low;
          found++;
        }
      }
      if (found == 0) {
        fprintf(stderr, "no secret completion at k=%d i=%d base=%d\n",
                i, j, base);
        return 6;
      }
      if (found > 1) ambiguous++;
    }
  }

  pack_sk(recovered_sk, rho, tr, &t0_rec, &s1_rec, &s2_rec);

  for (size_t i = 0; i < sizeof(seed); i++)
    seed[i] = (unsigned char)(0x5a ^ i);
  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 7;

  printf("ambiguous_t0_s2_positions=%u\n", ambiguous);
  printf("public_key_only_reconstruction=1\n");
  int all_forged = 1;
  for (int trial = 0; trial < 8; trial++) {
    unsigned long long forged_len = 0;
    snprintf((char *)msg, sizeof(msg),
             "fresh message after concurrent nonce recovery %d", trial);
    int sign_rc = sig_sign(recovered_sk, sk_len, msg, strlen((char *)msg),
                           forged_sig, &forged_len);
    int verify_rc = sig_verify(pk, pk_len, forged_sig, forged_len,
                               msg, strlen((char *)msg));
    printf("fresh_trial=%d sign_rc=%d len=%llu verify_rc=%d\n",
           trial, sign_rc, forged_len, verify_rc);
    all_forged &= sign_rc == 0 && verify_rc == 0;
  }
  printf("all_fresh_forgeries_verified=%d\n", all_forged);
  /*
   * Multiple (s2,t0) completions can satisfy the public relation.  The
   * cryptographic success condition is therefore a signing-equivalent key,
   * not byte equality with the hidden original secret key.
   */
  return all_forged ? 0 : 1;
}
