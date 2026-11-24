#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

extern int __real_get_random_number(DRNG_ctx *, unsigned char *,
                                    unsigned long long);

static pthread_barrier_t start_barrier;
static int thread_count;

typedef struct {
  int id;
  unsigned char output[CRHBYTES];
  int rc;
} probe_job;

int __wrap_get_random_number(DRNG_ctx *drng, unsigned char *out,
                             unsigned long long bits) {
  pthread_barrier_wait(&start_barrier);
  return __real_get_random_number(drng, out, bits);
}

static void *probe_thread(void *arg) {
  probe_job *job = arg;
  job->rc = get_random_number(&drng_algorithm, job->output, CRHBYTES * 8ULL);
  return NULL;
}

int main(int argc, char **argv) {
  thread_count = argc > 1 ? atoi(argv[1]) : 32;
  if (thread_count < 2 || thread_count > 256) {
    fprintf(stderr, "thread count must be in [2,256]\n");
    return 2;
  }

  unsigned char seed[64];
  for (size_t i = 0; i < sizeof(seed); i++)
    seed[i] = (unsigned char)(0x5a ^ i);
  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 3;

  probe_job *jobs = calloc((size_t)thread_count, sizeof(*jobs));
  pthread_t *threads = calloc((size_t)thread_count, sizeof(*threads));
  if (!jobs || !threads) return 4;
  pthread_barrier_init(&start_barrier, NULL, thread_count);

  for (int i = 0; i < thread_count; i++) {
    jobs[i].id = i;
    if (pthread_create(&threads[i], NULL, probe_thread, &jobs[i]) != 0)
      return 5;
  }
  for (int i = 0; i < thread_count; i++)
    pthread_join(threads[i], NULL);
  pthread_barrier_destroy(&start_barrier);

  unsigned int duplicate_pairs = 0;
  unsigned int duplicate_threads = 0;
  for (int i = 0; i < thread_count; i++) {
    int seen = 0;
    for (int j = i + 1; j < thread_count; j++) {
      if (jobs[i].rc == 0 && jobs[j].rc == 0 &&
          memcmp(jobs[i].output, jobs[j].output, CRHBYTES) == 0) {
        duplicate_pairs++;
        seen = 1;
      }
    }
    duplicate_threads += seen;
  }

  printf("threads=%d successful=%u duplicate_pairs=%u duplicate_threads=%u\n",
         thread_count,
         (unsigned int)thread_count,
         duplicate_pairs, duplicate_threads);

  free(threads);
  free(jobs);
  return duplicate_pairs == 0 ? 1 : 0;
}
