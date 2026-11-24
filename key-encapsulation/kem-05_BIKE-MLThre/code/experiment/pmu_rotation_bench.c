#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "defs.h"
#include "types.h"
#include "conversions.h"
#include "decode_ml.h"
#include "kem.h"
#include "ntl.h"
#include "FromNIST/rng.h"

void recompute_syndrome(uint8_t s[R_BITS], uint32_t pos,
                        const uint32_t h0_compact[DV],
                        const uint32_t h1_compact[DV]);

#define NKEYS 3U
#define NWEIGHTS 4U
#define NMASKS 4U
#define NSHIFTS 16U
#define NUNITS (NKEYS * NWEIGHTS * NMASKS * NSHIFTS)
#define REPS 3U

static const uint8_t key_bytes[NKEYS] = {0x42, 0x43, 0x44};
static const uint32_t public_weights[NWEIGHTS] = {8, 32, 128, 512};

typedef struct {
  uint8_t c0[R_SIZE];
  uint8_t s0[R_BITS];
  uint8_t s[R_BITS];
  uint8_t e[N_BITS];
  uint32_t h0[DV], h1[DV];
  uint32_t key_id, weight_id, mask_id, shift;
  uint32_t syndrome_weight, decoder_rc, final_weight, guess_weight;
} unit_t;

typedef struct {
  uint64_t branches, branch_misses, cycles;
} counters_t;

typedef struct {
  counters_t c;
  uint32_t syndrome_weight, decoder_rc, final_weight, guess_weight;
} row_t;

static unit_t units[NUNITS];
static row_t rows[NUNITS * REPS];
static uint32_t order[NUNITS];

static uint64_t splitmix64(uint64_t *state) {
  uint64_t z = (*state += UINT64_C(0x9e3779b97f4a7c15));
  z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
  return z ^ (z >> 31);
}

static unsigned get_bit(const uint8_t *bits, uint32_t pos) {
  return (bits[pos >> 3] >> (pos & 7U)) & 1U;
}

static void set_bit(uint8_t *bits, uint32_t pos) {
  bits[pos >> 3] |= (uint8_t)(1U << (pos & 7U));
}

static void rotate_polynomial(uint8_t out[R_SIZE], const uint8_t in[R_SIZE],
                              uint32_t shift) {
  memset(out, 0, R_SIZE);
  for (uint32_t i = 0; i < R_BITS; ++i)
    if (get_bit(in, i)) set_bit(out, (i + shift) % R_BITS);
}

static void make_mask(uint8_t c0[R_SIZE], uint32_t weight, uint64_t *rng) {
  uint16_t p[R_BITS];
  memset(c0, 0, R_SIZE);
  for (uint32_t i = 0; i < R_BITS; ++i) p[i] = (uint16_t)i;
  for (uint32_t i = 0; i < weight; ++i) {
    uint32_t j = i + (uint32_t)(splitmix64(rng) % (R_BITS - i));
    uint16_t t = p[i];
    p[i] = p[j];
    p[j] = t;
    set_bit(c0, p[i]);
  }
}

static uint32_t dense_weight(const uint8_t *bits, uint32_t nbits) {
  uint32_t w = 0;
  for (uint32_t i = 0; i < nbits; ++i) w += bits[i] != 0;
  return w;
}

static void syndrome_from_key(uint8_t s[R_BITS], const uint8_t c0[R_SIZE],
                              const sk_t *sk) {
  uint8_t product[R_SIZE] = {0}, linear[R_BITS] = {0};
  ntl_mod_mul(product, sk->val0, c0);
  convertByteToBinary(linear, product, R_BITS);
  transpose(s, linear);
}

static uint32_t sparse_syndrome_weight(const uint8_t c0[R_SIZE],
                                       const uint32_t h0[DV],
                                       const uint32_t h1[DV]) {
  uint8_t s[R_BITS] = {0};
  for (uint32_t pos = 0; pos < R_BITS; ++pos) {
    if (get_bit(c0, pos)) {
      uint32_t adjusted = pos == 0 ? 0 : R_BITS - pos;
      recompute_syndrome(s, adjusted, h0, h1);
    }
  }
  return dense_weight(s, R_BITS);
}

static void pin_cpu(void) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(0, sizeof(set), &set))
    fprintf(stderr, "warning: sched_setaffinity: %s\n", strerror(errno));
}

static int perf_open(unsigned long long config) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = PERF_TYPE_HARDWARE;
  attr.size = sizeof(attr);
  attr.config = config;
  attr.disabled = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  return (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

static int open_events(int fd[3]) {
  fd[0] = perf_open(PERF_COUNT_HW_BRANCH_INSTRUCTIONS);
  fd[1] = perf_open(PERF_COUNT_HW_BRANCH_MISSES);
  fd[2] = perf_open(PERF_COUNT_HW_CPU_CYCLES);
  for (int i = 0; i < 3; ++i) {
    if (fd[i] < 0) {
      fprintf(stderr, "perf event %d unavailable: %s\n", i, strerror(errno));
      return -1;
    }
  }
  return 0;
}

static void prepare_unit(unit_t *u) {
  memset(u->e, 0, sizeof(u->e));
  memcpy(u->s, u->s0, R_BITS);
}

static void run_unit(int fd[3], unit_t *u, row_t *out) {
  prepare_unit(u);
  for (int i = 0; i < 3; ++i) ioctl(fd[i], PERF_EVENT_IOC_RESET, 0);
  for (int i = 0; i < 3; ++i) ioctl(fd[i], PERF_EVENT_IOC_ENABLE, 0);
  out->decoder_rc =
      (uint32_t)BGF_decoder(u->e, u->s, u->h0, u->h1);
  for (int i = 0; i < 3; ++i) ioctl(fd[i], PERF_EVENT_IOC_DISABLE, 0);
  if (read(fd[0], &out->c.branches, 8) != 8 ||
      read(fd[1], &out->c.branch_misses, 8) != 8 ||
      read(fd[2], &out->c.cycles, 8) != 8) {
    perror("read perf counter");
    exit(3);
  }
  out->syndrome_weight = u->syndrome_weight;
  out->final_weight = dense_weight(u->s, R_BITS);
  out->guess_weight = dense_weight(u->e, N_BITS);
}

int main(int argc, char **argv) {
  const char *out_path = argc > 1 ? argv[1] : "pmu_rotation_rows.csv";
  uint64_t mask_rng = UINT64_C(0x243f6a8885a308d3);
  uint64_t shuffle_rng = UINT64_C(0x13198a2e03707344);
  uint32_t idx = 0;

  pin_cpu();
  for (uint32_t key_id = 0; key_id < NKEYS; ++key_id) {
    uint8_t seed[48], pk[sizeof(pk_t)];
    sk_t sk;
    memset(seed, key_bytes[key_id], sizeof(seed));
    randombytes_init(seed, NULL, 256);
    if (crypto_kem_keypair(pk, (uint8_t *)&sk)) return 2;
    for (uint32_t weight_id = 0; weight_id < NWEIGHTS; ++weight_id) {
      for (uint32_t mask_id = 0; mask_id < NMASKS; ++mask_id) {
        uint8_t c0[R_SIZE];
        make_mask(c0, public_weights[weight_id], &mask_rng);
        for (uint32_t shift = 0; shift < NSHIFTS; ++shift) {
          unit_t *u = &units[idx];
          sk_t rotated = sk;
          rotate_polynomial(rotated.val0, sk.val0, shift);
          rotate_polynomial(rotated.val1, sk.val1, shift);
          memcpy(u->c0, c0, R_SIZE);
          syndrome_from_key(u->s0, c0, &rotated);
          convert2compact(u->h0, rotated.val0);
          convert2compact(u->h1, rotated.val1);
          u->key_id = key_id;
          u->weight_id = weight_id;
          u->mask_id = mask_id;
          u->shift = shift;
          u->syndrome_weight = dense_weight(u->s0, R_BITS);
          uint32_t sparse = sparse_syndrome_weight(c0, u->h0, u->h1);
          if (sparse != u->syndrome_weight) {
            fprintf(stderr,
                    "oracle mismatch key=%u weight=%u mask=%u shift=%u dense=%u sparse=%u\n",
                    key_id, weight_id, mask_id, shift, u->syndrome_weight,
                    sparse);
            return 4;
          }
          ++idx;
        }
      }
    }
  }
  if (idx != NUNITS) return 5;

  int fd[3];
  if (open_events(fd)) return 6;
  /* Warm every code path before retained measurements. */
  for (uint32_t i = 0; i < NUNITS; ++i) {
    row_t discard;
    prepare_unit(&units[i]);
    discard.decoder_rc =
        (uint32_t)BGF_decoder(units[i].e, units[i].s, units[i].h0, units[i].h1);
  }
  for (uint32_t i = 0; i < NUNITS; ++i) order[i] = i;
  for (uint32_t r = 0; r < REPS; ++r) {
    for (uint32_t i = NUNITS - 1; i > 0; --i) {
      uint32_t j = (uint32_t)(splitmix64(&shuffle_rng) % (i + 1));
      uint32_t t = order[i];
      order[i] = order[j];
      order[j] = t;
    }
    for (uint32_t p = 0; p < NUNITS; ++p)
      run_unit(fd, &units[order[p]], &rows[(size_t)r * NUNITS + order[p]]);
  }
  for (int i = 0; i < 3; ++i) close(fd[i]);

  FILE *f = fopen(out_path, "w");
  if (!f) return 7;
  fprintf(f,
          "rep,key_id,weight_id,mask_id,shift,c0_weight,syndrome_weight,"
          "decoder_rc,final_weight,guess_weight,branches,branch_misses,cycles\n");
  for (uint32_t r = 0; r < REPS; ++r) {
    for (uint32_t i = 0; i < NUNITS; ++i) {
      unit_t *u = &units[i];
      row_t *x = &rows[(size_t)r * NUNITS + i];
      fprintf(f,
              "%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%llu,%llu,%llu\n",
              r, u->key_id, u->weight_id, u->mask_id, u->shift,
              public_weights[u->weight_id], x->syndrome_weight,
              x->decoder_rc, x->final_weight, x->guess_weight,
              (unsigned long long)x->c.branches,
              (unsigned long long)x->c.branch_misses,
              (unsigned long long)x->c.cycles);
    }
  }
  fclose(f);
  printf("{\"status\":\"completed\",\"units\":%u,\"rows\":%u,"
         "\"reps\":%u,\"oracle_validation\":\"all_matched\"}\n",
         NUNITS, NUNITS * REPS, REPS);
  return 0;
}
