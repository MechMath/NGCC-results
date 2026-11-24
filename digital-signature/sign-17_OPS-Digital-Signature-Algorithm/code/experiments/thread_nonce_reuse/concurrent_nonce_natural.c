#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"

DRNG_ctx drng_algorithm;

extern int __real_get_random_number(DRNG_ctx *, unsigned char *,
                                    unsigned long long);

typedef struct {
  const unsigned char *sk;
  unsigned char msg[32];
  unsigned char *sig;
  unsigned long long siglen;
  int sign_rc;
  int verify_rc;
  unsigned char rhoprime[CRHBYTES];
} sign_job;

static pthread_barrier_t nonce_barrier;
static sign_job *jobs;
static _Thread_local int thread_slot = -1;
static atomic_int sign_stage = 0;

int __wrap_get_random_number(DRNG_ctx *drng, unsigned char *out,
                             unsigned long long bits) {
  if (atomic_load_explicit(&sign_stage, memory_order_acquire) &&
      bits == (unsigned long long)CRHBYTES * 8ULL) {
    pthread_barrier_wait(&nonce_barrier);
  }
  int rc = __real_get_random_number(drng, out, bits);
  if (rc == 0 && atomic_load_explicit(&sign_stage, memory_order_acquire) &&
      bits == (unsigned long long)CRHBYTES * 8ULL &&
      thread_slot >= 0) {
    memcpy(jobs[thread_slot].rhoprime, out, CRHBYTES);
  }
  return rc;
}

static void *sign_thread(void *arg) {
  int slot = *(int *)arg;
  thread_slot = slot;
  sign_job *job = &jobs[slot];
  job->siglen = 0;
  job->sign_rc = sig_sign((unsigned char *)job->sk, sig_get_sk_len_bytes(),
                          job->msg, sizeof(job->msg), job->sig,
                          &job->siglen);
  return NULL;
}

static int write_file(const char *path, const void *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f) {
    perror(path);
    return 1;
  }
  if (fwrite(data, 1, len, f) != len) {
    perror(path);
    fclose(f);
    return 1;
  }
  return fclose(f) != 0;
}

static int write_i32_array(const char *path, const int32_t *v, size_t n) {
  return write_file(path, v, n * sizeof(*v));
}

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: concurrent_nonce_natural ARTIFACT_DIR [THREADS]\n");
    return 2;
  }
  const char *outdir = argv[1];
  int count = argc == 3 ? atoi(argv[2]) : 16;
  if (count < 2 || count > 256) {
    fprintf(stderr, "THREADS must be in [2,256]\n");
    return 2;
  }

  unsigned char *pk = calloc(1, sig_get_pk_len_bytes());
  unsigned char *sk = calloc(1, sig_get_sk_len_bytes());
  unsigned long long pk_len = 0, sk_len = 0;
  unsigned char seed[64];
  if (!pk || !sk) return 3;
  for (size_t i = 0; i < sizeof(seed); i++)
    seed[i] = (unsigned char)(0x5a ^ i);
  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 4;
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) return 5;

  jobs = calloc((size_t)count, sizeof(*jobs));
  int *slots = calloc((size_t)count, sizeof(*slots));
  pthread_t *threads = calloc((size_t)count, sizeof(*threads));
  if (!jobs || !slots || !threads) return 6;
  for (int i = 0; i < count; i++) {
    jobs[i].sk = sk;
    jobs[i].sig = calloc(1, sig_get_sn_len_bytes());
    if (!jobs[i].sig) return 7;
    for (size_t j = 0; j < sizeof(jobs[i].msg); j++)
      jobs[i].msg[j] = (unsigned char)(i ^ j ^ (j << 4));
    slots[i] = i;
  }

  pthread_barrier_init(&nonce_barrier, NULL, count);
  atomic_store_explicit(&sign_stage, 1, memory_order_release);
  for (int i = 0; i < count; i++)
    if (pthread_create(&threads[i], NULL, sign_thread, &slots[i]) != 0)
      return 8;
  for (int i = 0; i < count; i++)
    pthread_join(threads[i], NULL);
  atomic_store_explicit(&sign_stage, 0, memory_order_release);
  pthread_barrier_destroy(&nonce_barrier);

  int pair0 = -1, pair1 = -1;
  unsigned int duplicate_pairs = 0;
  for (int i = 0; i < count; i++) {
    for (int j = i + 1; j < count; j++) {
      if (jobs[i].sign_rc == 0 && jobs[j].sign_rc == 0 &&
          jobs[i].siglen == sig_get_sn_len_bytes() &&
          jobs[j].siglen == sig_get_sn_len_bytes() &&
          memcmp(jobs[i].rhoprime, jobs[j].rhoprime, CRHBYTES) == 0) {
        duplicate_pairs++;
        if (pair0 < 0) {
          pair0 = i;
          pair1 = j;
        }
      }
    }
  }
  printf("threads=%d duplicate_pairs=%u selected_pair=(%d,%d)\n",
         count, duplicate_pairs, pair0, pair1);
  if (pair0 < 0) {
    free(threads);
    free(slots);
    for (int i = 0; i < count; i++) free(jobs[i].sig);
    free(jobs);
    free(sk);
    free(pk);
    return 1;
  }

  int verify0 = sig_verify(pk, pk_len, jobs[pair0].sig,
                           jobs[pair0].siglen, jobs[pair0].msg,
                           sizeof(jobs[pair0].msg));
  int verify1 = sig_verify(pk, pk_len, jobs[pair1].sig,
                           jobs[pair1].siglen, jobs[pair1].msg,
                           sizeof(jobs[pair1].msg));
  printf("selected_sign_rc=(%d,%d) selected_verify_rc=(%d,%d)\n",
         jobs[pair0].sign_rc, jobs[pair1].sign_rc, verify0, verify1);
  if (verify0 != 0 || verify1 != 0) return 9;

  char path[1024];
  snprintf(path, sizeof(path), "%s/publickey.bin", outdir);
  if (write_file(path, pk, pk_len)) return 10;
  snprintf(path, sizeof(path), "%s/secretkey.bin", outdir);
  if (write_file(path, sk, sk_len)) return 10;
  for (int which = 0; which < 2; which++) {
    int job = which == 0 ? pair0 : pair1;
    snprintf(path, sizeof(path), "%s/signature%d.bin", outdir, which);
    if (write_file(path, jobs[job].sig, jobs[job].siglen)) return 10;
    snprintf(path, sizeof(path), "%s/message%d.bin", outdir, which);
    if (write_file(path, jobs[job].msg, sizeof(jobs[job].msg))) return 10;
    snprintf(path, sizeof(path), "%s/rhoprime%d.bin", outdir, which);
    if (write_file(path, jobs[job].rhoprime, CRHBYTES)) return 10;
  }

  uint8_t rho[SEEDBYTES], tr[CRHBYTES];
  polyvecl s1_true;
  polyveck t0, s2;
  unpack_sk(rho, tr, &t0, &s1_true, &s2, sk);

  uint8_t cseed[2][CTILDEBYTES];
  polyvecl z[2];
  polyveck hint[2];
  poly challenge[2];
  for (int which = 0; which < 2; which++) {
    int job = which == 0 ? pair0 : pair1;
    if (unpack_sig(cseed[which], &z[which], &hint[which],
                   jobs[job].sig))
      return 11;
    poly_challenge(&challenge[which], cseed[which]);
  }
  for (int i = 0; i < L; i++) {
    snprintf(path, sizeof(path), "%s/s1_true_%d.i32", outdir, i);
    if (write_i32_array(path, s1_true.vec[i].coeffs, N)) return 12;
    snprintf(path, sizeof(path), "%s/z0_%d.i32", outdir, i);
    if (write_i32_array(path, z[0].vec[i].coeffs, N)) return 12;
    snprintf(path, sizeof(path), "%s/z1_%d.i32", outdir, i);
    if (write_i32_array(path, z[1].vec[i].coeffs, N)) return 12;
  }
  snprintf(path, sizeof(path), "%s/c0.i32", outdir);
  if (write_i32_array(path, challenge[0].coeffs, N)) return 12;
  snprintf(path, sizeof(path), "%s/c1.i32", outdir);
  if (write_i32_array(path, challenge[1].coeffs, N)) return 12;

  free(threads);
  free(slots);
  for (int i = 0; i < count; i++) free(jobs[i].sig);
  free(jobs);
  free(sk);
  free(pk);
  return 0;
}
