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

static atomic_int sign_stage = 0;
static atomic_int deterministic_same_state = 0;
static pthread_barrier_t nonce_barrier;
static pthread_barrier_t snapshot_barrier;
static pthread_mutex_t record_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned char observed_rhoprime[2][CRHBYTES];
static atomic_int observed_count = 0;

int __wrap_get_random_number(DRNG_ctx *drng, unsigned char *out,
                             unsigned long long bits) {
  if (atomic_load_explicit(&sign_stage, memory_order_acquire) &&
      bits == (unsigned long long)CRHBYTES * 8ULL) {
    pthread_barrier_wait(&nonce_barrier);
  }

  int rc;
  if (atomic_load_explicit(&sign_stage, memory_order_acquire) &&
      bits == (unsigned long long)CRHBYTES * 8ULL &&
      atomic_load_explicit(&deterministic_same_state, memory_order_acquire)) {
    /*
     * Realize a legal preemption point before SM3_DRNG_Generate's
     * memcpy(data, drng->V, SEEDLEN): both calls read the same DRNG state.
     */
    DRNG_ctx snapshot = *drng;
    pthread_barrier_wait(&snapshot_barrier);
    rc = __real_get_random_number(&snapshot, out, bits);
  } else {
    rc = __real_get_random_number(drng, out, bits);
  }

  if (atomic_load_explicit(&sign_stage, memory_order_acquire) &&
      bits == (unsigned long long)CRHBYTES * 8ULL && rc == 0) {
    int slot = atomic_fetch_add_explicit(&observed_count, 1,
                                         memory_order_relaxed);
    if (slot >= 0 && slot < 2) {
      pthread_mutex_lock(&record_lock);
      memcpy(observed_rhoprime[slot], out, CRHBYTES);
      pthread_mutex_unlock(&record_lock);
    }
  }
  return rc;
}

typedef struct {
  const unsigned char *sk;
  unsigned char *msg;
  size_t msglen;
  unsigned char *sig;
  unsigned long long siglen;
  int rc;
} sign_job;

static void *sign_thread(void *arg) {
  sign_job *job = (sign_job *)arg;
  job->siglen = 0;
  job->rc = sig_sign((unsigned char *)job->sk, sig_get_sk_len_bytes(),
                     job->msg, job->msglen, job->sig, &job->siglen);
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
  const char *outdir = argc > 1 ? argv[1] : ".";
  char path[1024];
  unsigned char seed[64];
  unsigned char *pk = calloc(1, sig_get_pk_len_bytes());
  unsigned char *sk = calloc(1, sig_get_sk_len_bytes());
  unsigned char *sigs[2] = {
      calloc(1, sig_get_sn_len_bytes()),
      calloc(1, sig_get_sn_len_bytes()),
  };
  unsigned char msgs[2][32];
  unsigned long long pk_len = 0, sk_len = 0;

  if (!pk || !sk || !sigs[0] || !sigs[1]) {
    fprintf(stderr, "allocation failure\n");
    return 2;
  }
  for (size_t i = 0; i < sizeof(seed); i++)
    seed[i] = (unsigned char)(0x5a ^ i);
  for (size_t i = 0; i < sizeof(msgs[0]); i++) {
    msgs[0][i] = (unsigned char)i;
    msgs[1][i] = (unsigned char)(0xa0 + i);
  }

  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
    fprintf(stderr, "DRNG initialization failed\n");
    return 3;
  }
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
    fprintf(stderr, "key generation failed\n");
    return 4;
  }
  if (pk_len != sig_get_pk_len_bytes() ||
      sk_len != sig_get_sk_len_bytes()) {
    fprintf(stderr, "unexpected key lengths %llu %llu\n", pk_len, sk_len);
    return 5;
  }

  pthread_barrier_init(&nonce_barrier, NULL, 2);
  pthread_barrier_init(&snapshot_barrier, NULL, 2);
  if (getenv("OPS_SCHEDULE_SAME_STATE") &&
      strcmp(getenv("OPS_SCHEDULE_SAME_STATE"), "1") == 0)
    atomic_store_explicit(&deterministic_same_state, 1, memory_order_release);
  atomic_store_explicit(&sign_stage, 1, memory_order_release);

  sign_job jobs[2] = {
      {.sk = sk, .msg = msgs[0], .msglen = sizeof(msgs[0]),
       .sig = sigs[0]},
      {.sk = sk, .msg = msgs[1], .msglen = sizeof(msgs[1]),
       .sig = sigs[1]},
  };
  pthread_t threads[2];
  for (int i = 0; i < 2; i++)
    if (pthread_create(&threads[i], NULL, sign_thread, &jobs[i]) != 0)
      return 6;
  for (int i = 0; i < 2; i++)
    pthread_join(threads[i], NULL);

  atomic_store_explicit(&sign_stage, 0, memory_order_release);
  pthread_barrier_destroy(&nonce_barrier);
  pthread_barrier_destroy(&snapshot_barrier);

  int rho_equal = memcmp(observed_rhoprime[0], observed_rhoprime[1],
                         CRHBYTES) == 0;
  int verify[2];
  for (int i = 0; i < 2; i++)
    verify[i] = sig_verify(pk, pk_len, sigs[i], jobs[i].siglen, msgs[i],
                           sizeof(msgs[i]));

  printf("sign_rc_0=%d sign_len_0=%llu\n", jobs[0].rc, jobs[0].siglen);
  printf("sign_rc_1=%d sign_len_1=%llu\n", jobs[1].rc, jobs[1].siglen);
  printf("verify_0=%d verify_1=%d\n", verify[0], verify[1]);
  printf("observed_nonce_requests=%d duplicate_rhoprime=%d\n",
         atomic_load(&observed_count), rho_equal);
  printf("deterministic_same_precall_state=%d\n",
         atomic_load(&deterministic_same_state));

  snprintf(path, sizeof(path), "%s/publickey.bin", outdir);
  if (write_file(path, pk, pk_len)) return 7;
  snprintf(path, sizeof(path), "%s/secretkey.bin", outdir);
  if (write_file(path, sk, sk_len)) return 7;
  snprintf(path, sizeof(path), "%s/signature0.bin", outdir);
  if (write_file(path, sigs[0], jobs[0].siglen)) return 7;
  snprintf(path, sizeof(path), "%s/signature1.bin", outdir);
  if (write_file(path, sigs[1], jobs[1].siglen)) return 7;
  snprintf(path, sizeof(path), "%s/message0.bin", outdir);
  if (write_file(path, msgs[0], sizeof(msgs[0]))) return 7;
  snprintf(path, sizeof(path), "%s/message1.bin", outdir);
  if (write_file(path, msgs[1], sizeof(msgs[1]))) return 7;
  snprintf(path, sizeof(path), "%s/rhoprime0.bin", outdir);
  if (write_file(path, observed_rhoprime[0], CRHBYTES)) return 7;
  snprintf(path, sizeof(path), "%s/rhoprime1.bin", outdir);
  if (write_file(path, observed_rhoprime[1], CRHBYTES)) return 7;

  uint8_t rho[SEEDBYTES], tr[CRHBYTES];
  polyvecl s1_true;
  polyveck t0, s2;
  unpack_sk(rho, tr, &t0, &s1_true, &s2, sk);

  uint8_t cseed[2][CTILDEBYTES];
  polyvecl z[2];
  polyveck h[2];
  poly cpoly[2];
  if (unpack_sig(cseed[0], &z[0], &h[0], sigs[0]) ||
      unpack_sig(cseed[1], &z[1], &h[1], sigs[1])) {
    fprintf(stderr, "signature unpack failure\n");
    return 8;
  }
  poly_challenge(&cpoly[0], cseed[0]);
  poly_challenge(&cpoly[1], cseed[1]);

  for (int i = 0; i < L; i++) {
    snprintf(path, sizeof(path), "%s/s1_true_%d.i32", outdir, i);
    if (write_i32_array(path, s1_true.vec[i].coeffs, N)) return 9;
    snprintf(path, sizeof(path), "%s/z0_%d.i32", outdir, i);
    if (write_i32_array(path, z[0].vec[i].coeffs, N)) return 9;
    snprintf(path, sizeof(path), "%s/z1_%d.i32", outdir, i);
    if (write_i32_array(path, z[1].vec[i].coeffs, N)) return 9;
  }
  snprintf(path, sizeof(path), "%s/c0.i32", outdir);
  if (write_i32_array(path, cpoly[0].coeffs, N)) return 9;
  snprintf(path, sizeof(path), "%s/c1.i32", outdir);
  if (write_i32_array(path, cpoly[1].coeffs, N)) return 9;

  free(sigs[1]);
  free(sigs[0]);
  free(sk);
  free(pk);
  return 0;
}
