#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "auxfunc.h"
#include "drng.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void spec_decompose(int32_t *a0_out, int32_t a) {
  const int32_t alpha = 2 * GAMMA2;
  const int32_t m =
      GAMMA2 == (Q - 1) / 32 ? 16 :
      GAMMA2 == (Q - 1) / 48 ? 24 : 48;
  int32_t a1 = (int32_t)(((int64_t)a + GAMMA2) / alpha);
  int32_t a0;
  if (a1 == m) a1 = 0;
  a0 = a - a1 * alpha;
  if (a0 > (Q - 1) / 2) a0 -= Q;
  *a0_out = a0;
}

static int32_t spec_use_hint(int32_t a, unsigned int hint) {
  const int32_t m =
      GAMMA2 == (Q - 1) / 32 ? 16 :
      GAMMA2 == (Q - 1) / 48 ? 24 : 48;
  int32_t a0;
  int32_t a1;
  spec_decompose(&a0, a);
  a1 = (int32_t)(((int64_t)a + GAMMA2) / (2 * GAMMA2));
  if (a1 == m) a1 = 0;
  if (hint == 0) return a1;
  if (a0 > 0) return (a1 + 1) % m;
  return (a1 - 1 + m) % m;
}

static void spec_polyveck_use_hint(polyveck *w, const polyveck *u,
                                   const polyveck *h) {
  for (unsigned i = 0; i < K; ++i)
    for (unsigned j = 0; j < N; ++j)
      w->vec[i].coeffs[j] =
          spec_use_hint(u->vec[i].coeffs[j],
                        (unsigned int)h->vec[i].coeffs[j]);
}

static void crh(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
  pseudohash((unsigned long long)outlen * 8ULL, in,
             (unsigned long long)inlen * 8ULL, out);
}

/*
 * Preserve the exact submitted challenge-hash dispatch.  The submitted 128
 * verifier calls sm3hash(256,...), while the 256/512 verifiers call
 * pseudohash(CTILDEBYTES*8,...).
 */
static int challenge_hash(uint8_t *out, const uint8_t *in, size_t inlen) {
#if CTILDEBYTES == 32
  return sm3hash((unsigned long long)CTILDEBYTES * 8ULL, in,
                 (unsigned long long)inlen * 8ULL, out);
#else
  return pseudohash((unsigned long long)CTILDEBYTES * 8ULL, in,
                    (unsigned long long)inlen * 8ULL, out);
#endif
}

/*
 * This is the submitted Algorithm 3 verifier with only Decompose/UseHint
 * replaced by permitted-specification Algorithms 30/32. The mismatch count
 * records every verification coefficient on which the two UseHint maps differ.
 */
static int spec_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                       size_t mlen, const uint8_t *pk,
                       int *hash_length_supported,
                       unsigned *mismatch_count,
                       int *first_poly, int *first_coeff,
                       int32_t *first_a, int32_t *first_submitted,
                       int32_t *first_spec, int *first_hint) {
  uint8_t buf[K * POLYW1_PACKEDBYTES];
  uint8_t rho[SEEDBYTES];
  uint8_t mu[CRHBYTES];
  uint8_t tr[CRHBYTES];
  uint8_t c[CTILDEBYTES];
  uint8_t c2[CTILDEBYTES];
  uint8_t ctmp[CRHBYTES + K * POLYW1_PACKEDBYTES];
  uint8_t pre[2] = {0, 0};
  poly cp;
  polyvecl mat[K], z;
  polyveck t1, w1, wraw, wsub, h;

  *mismatch_count = 0;
  *hash_length_supported = 1;
  *first_poly = -1;
  *first_coeff = -1;
  *first_a = 0;
  *first_submitted = 0;
  *first_spec = 0;
  *first_hint = -1;

  if (siglen != CRYPTO_BYTES) return -1;
  unpack_pk(rho, &t1, pk);
  if (unpack_sig(c, &z, &h, sig)) return -1;
  if (polyvecl_chknorm(&z, GAMMA1 - BETA)) return -1;

  crh(tr, CRHBYTES, pk, CRYPTO_PUBLICKEYBYTES);
  size_t inlen = CRHBYTES + sizeof(pre) + mlen;
  uint8_t *tmp = malloc(inlen);
  if (!tmp) return -1;
  memcpy(tmp, tr, CRHBYTES);
  memcpy(tmp + CRHBYTES, pre, sizeof(pre));
  memcpy(tmp + CRHBYTES + sizeof(pre), m, mlen);
  crh(mu, CRHBYTES, tmp, inlen);
  free(tmp);

  poly_challenge(&cp, c);
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  poly_ntt(&cp);
  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);
  polyveck_sub(&w1, &w1, &t1);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);
  polyveck_caddq(&w1);

  wraw = w1;
  wsub = wraw;
  polyveck_use_hint(&wsub, &wraw, &h);
  spec_polyveck_use_hint(&w1, &wraw, &h);
  for (unsigned i = 0; i < K; ++i) {
    for (unsigned j = 0; j < N; ++j) {
      if (wsub.vec[i].coeffs[j] != w1.vec[i].coeffs[j]) {
        if (*first_poly < 0) {
          *first_poly = (int)i;
          *first_coeff = (int)j;
          *first_a = wraw.vec[i].coeffs[j];
          *first_submitted = wsub.vec[i].coeffs[j];
          *first_spec = w1.vec[i].coeffs[j];
          *first_hint = h.vec[i].coeffs[j];
          goto first_done;
        }
      }
    }
  }
first_done:
  for (unsigned i = 0; i < K; ++i)
    for (unsigned j = 0; j < N; ++j)
      if (wsub.vec[i].coeffs[j] != w1.vec[i].coeffs[j])
        ++*mismatch_count;

  polyveck_pack_w1(buf, &w1);
  memcpy(ctmp, mu, CRHBYTES);
  memcpy(ctmp + CRHBYTES, buf, K * POLYW1_PACKEDBYTES);
  int hash_rc = challenge_hash(c2, ctmp, sizeof(ctmp));
  if (hash_rc != 0) {
    *hash_length_supported = 0;
    return -2;
  }
  for (unsigned i = 0; i < CTILDEBYTES; ++i)
    if (c[i] != c2[i]) return -1;
  return 0;
}

static void print_hex(FILE *f, const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; ++i) fprintf(f, "%02x", p[i]);
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s PROFILE QUERIES OUTPUT_DIR\n", argv[0]);
    return 2;
  }
  const char *profile = argv[1];
  const unsigned queries = (unsigned)strtoul(argv[2], NULL, 10);
  const char *outdir = argv[3];
  if (queries != 256) {
    fprintf(stderr, "query budget is frozen at 256, got %u\n", queries);
    return 2;
  }

  char path[1024];
  snprintf(path, sizeof(path), "%s/attempts.csv", outdir);
  FILE *log = fopen(path, "w");
  if (!log) { perror(path); return 1; }
  snprintf(path, sizeof(path), "%s/signatures.bin", outdir);
  FILE *sigfile = fopen(path, "wb");
  if (!sigfile) { perror(path); return 1; }
  snprintf(path, sizeof(path), "%s/publickey.bin", outdir);
  FILE *pkfile = fopen(path, "wb");
  if (!pkfile) { perror(path); return 1; }

  unsigned char seed[55];
  for (unsigned i = 0; i < sizeof(seed); ++i) seed[i] = 0x5a ^ (unsigned char)i;
  init_random_number(&drng_algorithm, seed, sizeof(seed));

  unsigned long long pklen = sig_get_pk_len_bytes();
  unsigned long long sklen = sig_get_sk_len_bytes();
  unsigned long long siglen = sig_get_sn_len_bytes();
  uint8_t *pk = calloc(1, (size_t)pklen);
  uint8_t *sk = calloc(1, (size_t)sklen);
  uint8_t *sig = calloc(1, (size_t)siglen);
  uint8_t *tampered = calloc(1, (size_t)siglen);
  uint8_t msg[32];
  if (!pk || !sk || !sig || !tampered) return 1;

  uint64_t start_all = now_ns();
  if (sig_keygen(pk, &pklen, sk, &sklen) != 0) return 1;
  fwrite(pk, 1, (size_t)pklen, pkfile);

  fprintf(log, "query,message_hex,submitted_accept,spec_verifier_valid,"
               "spec_accept,spec_reject,"
               "usehint_mismatches,first_poly,first_coeff,first_a,submitted_high,"
               "spec_high,hint,cumulative_ns\n");
  unsigned submitted_accept = 0, spec_accept = 0, spec_reject = 0;
  unsigned spec_valid = 1;
  for (unsigned qi = 0; qi < queries; ++qi) {
    memset(msg, 0, sizeof(msg));
    memcpy(msg, "OPSBOUNDARY", 11);
    msg[16] = (uint8_t)strtoul(profile + 6, NULL, 10);
    for (unsigned b = 0; b < 8; ++b)
      msg[24 + b] = (uint8_t)(qi >> (56 - 8 * b));

    unsigned long long got_siglen = 0;
    if (sig_sign(sk, sklen, msg, sizeof(msg), sig, &got_siglen) != 0 ||
        got_siglen != siglen) {
      fprintf(stderr, "sign failed at query %u\n", qi);
      return 1;
    }
    int sub_ok = sig_verify(pk, pklen, sig, siglen, msg, sizeof(msg)) == 0;
    unsigned mismatches = 0;
    int fp = -1, fc = -1, fh = -1;
    int32_t fa = 0, fsub = 0, fspec = 0;
    int hash_length_supported = 1;
    int spec_ok = spec_verify(sig, siglen, msg, sizeof(msg), pk,
                              &hash_length_supported, &mismatches,
                              &fp, &fc, &fa, &fsub, &fspec, &fh) == 0;
    if (!hash_length_supported) {
      spec_valid = 0;
      spec_ok = 0;
    }
    submitted_accept += sub_ok;
    if (spec_valid) {
      spec_accept += spec_ok;
      spec_reject += !spec_ok;
    }
    fwrite(sig, 1, (size_t)siglen, sigfile);
    fprintf(log, "%u,", qi);
    print_hex(log, msg, sizeof(msg));
    fprintf(log, ",%d,%d,%d,%d,%u,%d,%d,%" PRId32 ",%" PRId32 ",%" PRId32
                 ",%d,%" PRIu64
                 "\n",
            sub_ok, hash_length_supported, spec_ok,
            hash_length_supported && !spec_ok, mismatches, fp, fc, fa, fsub, fspec, fh,
            now_ns() - start_all);
    if (!sub_ok) {
      fprintf(stderr, "positive control failed at query %u\n", qi);
      return 1;
    }
  }
  fclose(sigfile);
  fclose(pkfile);

  /* One negative control on the final signature: both paths must reject. */
  memcpy(tampered, sig, (size_t)siglen);
  tampered[0] ^= 1;
  memset(msg, 0, sizeof(msg));
  memcpy(msg, "OPSBOUNDARY-NEGATIVE", 20);
  int sub_neg = sig_verify(pk, pklen, tampered, siglen, msg, sizeof(msg)) == 0;
  unsigned nm = 0;
  int neg_hash_supported = 1;
  int fp = -1, fc = -1, fh = -1;
  int32_t fa = 0, fsub = 0, fspec = 0;
  int spec_neg =
      spec_verify(tampered, siglen, msg, sizeof(msg), pk, &neg_hash_supported,
                  &nm, &fp, &fc, &fa, &fsub, &fspec, &fh) == 0;
  fprintf(log, "NEGATIVE_CONTROL,,,,,,%u,%d,%d,%" PRId32 ",%" PRId32 ",%d,"
               "%" PRIu64 "\n", nm, fp, fc, fsub, fspec, fh,
          now_ns() - start_all);
  fclose(log);
  free(pk); free(sk); free(sig); free(tampered);

  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  printf("{\"profile\":\"%s\",\"queries\":%u,\"submitted_accept\":%u,"
         "\"spec_verifier_valid\":%s,\"spec_accept\":%u,\"spec_reject\":%u,"
         "\"submitted_negative_accept\":%d,\"spec_negative_accept\":%d,"
         "\"elapsed_ns\":%" PRIu64 ",\"maxrss_kib\":%ld,"
         "\"pk_bytes\":%llu,\"sk_bytes\":%llu,\"signature_bytes\":%llu}\n",
         profile, queries, submitted_accept, spec_valid ? "true" : "false",
         spec_accept, spec_reject,
         sub_neg, spec_neg, now_ns() - start_all, ru.ru_maxrss,
         pklen, sklen, siglen);
  return (submitted_accept == queries && sub_neg == 0 && spec_neg == 0) ? 0 : 1;
}
