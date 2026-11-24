/*
 * Independent local soundness experiment for Lynxer-160f.
 *
 * This file intentionally includes the original owf.c so that its static
 * field/map helpers can be reused. It does not modify the submitted source.
 */
#include "owf.c"

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "instances.h"
#include "voleith_impl.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CSP 160
#define WORDS 3
#define BYTES (CSP / 8)

DRNG_ctx drng_algorithm;

static int bit_get(const uint64_t words[WORDS], unsigned int bit) {
  return (int)((words[bit / 64] >> (bit % 64)) & 1u);
}

static void bit_set(uint64_t words[WORDS], unsigned int bit) {
  words[bit / 64] |= UINT64_C(1) << (bit % 64);
}

static int is_zero(const uint64_t words[WORDS]) {
  return (words[0] | words[1] | words[2]) == 0;
}

static unsigned int rank_bitset(const uint64_t input[CSP][WORDS]) {
  uint64_t rows[CSP][WORDS];
  memcpy(rows, input, sizeof(rows));
  unsigned int rank = 0;
  for (unsigned int col = 0; col < CSP; ++col) {
    unsigned int pivot = rank;
    while (pivot < CSP && !bit_get(rows[pivot], col)) {
      ++pivot;
    }
    if (pivot == CSP) {
      continue;
    }
    if (pivot != rank) {
      for (unsigned int w = 0; w < WORDS; ++w) {
        const uint64_t t = rows[rank][w];
        rows[rank][w] = rows[pivot][w];
        rows[pivot][w] = t;
      }
    }
    for (unsigned int row = rank + 1; row < CSP; ++row) {
      if (bit_get(rows[row], col)) {
        for (unsigned int w = 0; w < WORDS; ++w) {
          rows[row][w] ^= rows[rank][w];
        }
      }
    }
    ++rank;
  }
  return rank;
}

/*
 * Solve A x = y over GF(2). A is supplied by its columns.
 * Returns 1 for a unique solution and stores it in x.
 */
static int solve_columns(const uint64_t columns[CSP][WORDS], const uint64_t y[WORDS],
                         uint64_t x[WORDS], unsigned int *rank_out) {
  uint64_t rows[CSP][WORDS] = {{0}};
  uint64_t rhs[CSP] = {0};
  unsigned int rank = 0;

  for (unsigned int row = 0; row < CSP; ++row) {
    for (unsigned int col = 0; col < CSP; ++col) {
      if (bit_get(columns[col], row)) {
        bit_set(rows[row], col);
      }
    }
    rhs[row] = bit_get(y, row);
  }

  for (unsigned int col = 0; col < CSP; ++col) {
    unsigned int pivot = rank;
    while (pivot < CSP && !bit_get(rows[pivot], col)) {
      ++pivot;
    }
    if (pivot == CSP) {
      continue;
    }
    if (pivot != rank) {
      for (unsigned int w = 0; w < WORDS; ++w) {
        const uint64_t t = rows[rank][w];
        rows[rank][w] = rows[pivot][w];
        rows[pivot][w] = t;
      }
      const uint64_t t = rhs[rank];
      rhs[rank] = rhs[pivot];
      rhs[pivot] = t;
    }
    for (unsigned int row = 0; row < CSP; ++row) {
      if (row != rank && bit_get(rows[row], col)) {
        for (unsigned int w = 0; w < WORDS; ++w) {
          rows[row][w] ^= rows[rank][w];
        }
        rhs[row] ^= rhs[rank];
      }
    }
    ++rank;
  }

  *rank_out = rank;
  for (unsigned int row = rank; row < CSP; ++row) {
    if (rhs[row]) {
      return 0;
    }
  }

  memset(x, 0, WORDS * sizeof(uint64_t));
  for (unsigned int row = 0; row < rank; ++row) {
    for (unsigned int col = 0; col < CSP; ++col) {
      if (bit_get(rows[row], col)) {
        if (rhs[row]) {
          bit_set(x, col);
        }
        break;
      }
    }
  }
  return 1;
}

static bf160_t map_apply(const uint64_t map[CSP][WORDS], bf160_t x) {
  return lynx_L160(map, x);
}

static unsigned int executed_map_rank(const uint64_t map[CSP][WORDS]) {
  uint64_t images[CSP][WORDS] = {{0}};
  for (unsigned int col = 0; col < CSP; ++col) {
    bf160_t e = bf160_zero();
    BF_VALUE(e, col / 64) = UINT64_C(1) << (col % 64);
    const bf160_t image = map_apply(map, e);
    images[col][0] = BF_VALUE(image, 0);
    images[col][1] = BF_VALUE(image, 1);
    images[col][2] = BF_VALUE(image, 2);
  }
  return rank_bitset(images);
}

/*
 * T(v) = L1(v1) * L2(v) + L3(k + v1 + v). Its columns are
 * T(e_j) + T(0).
 */
static int make_t_columns(const lynx_t *mats, bf160_t v1, bf160_t k,
                          uint64_t columns[CSP][WORDS], uint64_t base[WORDS]) {
  const uint64_t (*L2)[WORDS] = (const uint64_t (*)[WORDS])mats->L2;
  const uint64_t (*L3)[WORDS] = (const uint64_t (*)[WORDS])mats->L3;
  const bf160_t alpha = map_apply((const uint64_t (*)[WORDS])mats->L1, v1);
  const bf160_t t0 = map_apply(L3, bf160_add(k, v1));

  for (unsigned int col = 0; col < CSP; ++col) {
    bf160_t e = bf160_zero();
    BF_VALUE(e, col / 64) = UINT64_C(1) << (col % 64);
    const bf160_t image = bf160_add(bf160_mul(alpha, map_apply(L2, e)), map_apply(L3, e));
    columns[col][0] = BF_VALUE(image, 0);
    columns[col][1] = BF_VALUE(image, 1);
    columns[col][2] = BF_VALUE(image, 2);
  }

  base[0] = BF_VALUE(t0, 0);
  base[1] = BF_VALUE(t0, 1);
  base[2] = BF_VALUE(t0, 2);
  return 1;
}

static int try_public_key(unsigned int attempt, const sig_paramset_t *params,
                          unsigned char *pk, unsigned char *sk, unsigned char *sig,
                          unsigned char *witness, unsigned char *forged_key,
                          bf160_t *out_k, bf160_t *out_v1, bf160_t *out_v2) {
  const unsigned char msg[] = "Lynxer-160f invalid-witness acceptance experiment";
  static const unsigned char kat_pk[40] = {
      0x81, 0x57, 0x88, 0x6d, 0x49, 0xd8, 0x32, 0x3c, 0x19, 0x8c,
      0x19, 0x42, 0xb9, 0x63, 0xae, 0x68, 0xf3, 0xe4, 0xac, 0xec,
      0xd4, 0xc5, 0x42, 0x18, 0xa9, 0x18, 0x40, 0xac, 0xe5, 0x48,
      0xb6, 0x94, 0x8e, 0xeb, 0x3d, 0x3d, 0xde, 0x82, 0x51, 0x77,
  };
  const unsigned char rho[BYTES] = {0};
  unsigned long long pk_len = 40;
  unsigned long long sk_len = 40;
  unsigned long long sig_len = 5801;

  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
    fprintf(stderr, "sig_keygen failed\n");
    return 0;
  }
  memcpy(pk, kat_pk, sizeof(kat_pk));

  lynx_t mats;
  if (lynx_init(&mats, CSP, pk, BYTES) != 0) {
    fprintf(stderr, "lynx_init failed\n");
    return 0;
  }

  const uint64_t (*L0)[WORDS] = (const uint64_t (*)[WORDS])mats.L0;
  const uint64_t (*L1)[WORDS] = (const uint64_t (*)[WORDS])mats.L1;
  const uint64_t (*L2)[WORDS] = (const uint64_t (*)[WORDS])mats.L2;
  const uint64_t (*L3)[WORDS] = (const uint64_t (*)[WORDS])mats.L3;
  const bf160_t c0 = bf160_load(mats.C0);
  const bf160_t t = bf160_load(pk + BYTES);

  uint64_t identity_columns[CSP][WORDS] = {{0}};
  for (unsigned int col = 0; col < CSP; ++col) {
    bit_set(identity_columns[col], col);
  }

  uint64_t c0_words[WORDS] = {
      BF_VALUE(c0, 0),
      BF_VALUE(c0, 1),
      BF_VALUE(c0, 2),
  };
  uint64_t k_words[WORDS] = {0};
  uint64_t images[CSP][WORDS] = {{0}};
  unsigned int rank = 0;
  for (unsigned int col = 0; col < CSP; ++col) {
    bf160_t e = bf160_zero();
    BF_VALUE(e, col / 64) = UINT64_C(1) << (col % 64);
    const bf160_t image = map_apply(L0, e);
    images[col][0] = BF_VALUE(image, 0);
    images[col][1] = BF_VALUE(image, 1);
    images[col][2] = BF_VALUE(image, 2);
  }
  if (!solve_columns(images, c0_words, k_words, &rank)) {
    const uint64_t direct[CSP][WORDS] = {
        {L0[0][0], L0[0][1], L0[0][2]},
        {L0[1][0], L0[1][1], L0[1][2]},
        {L0[2][0], L0[2][1], L0[2][2]},
        {L0[3][0], L0[3][1], L0[3][2]},
        {L0[4][0], L0[4][1], L0[4][2]},
        {L0[5][0], L0[5][1], L0[5][2]},
        {L0[6][0], L0[6][1], L0[6][2]},
        {L0[7][0], L0[7][1], L0[7][2]},
        {L0[8][0], L0[8][1], L0[8][2]},
        {L0[9][0], L0[9][1], L0[9][2]},
        {L0[10][0], L0[10][1], L0[10][2]},
        {L0[11][0], L0[11][1], L0[11][2]},
        {L0[12][0], L0[12][1], L0[12][2]},
        {L0[13][0], L0[13][1], L0[13][2]},
        {L0[14][0], L0[14][1], L0[14][2]},
        {L0[15][0], L0[15][1], L0[15][2]},
        {L0[16][0], L0[16][1], L0[16][2]},
        {L0[17][0], L0[17][1], L0[17][2]},
        {L0[18][0], L0[18][1], L0[18][2]},
        {L0[19][0], L0[19][1], L0[19][2]},
        {L0[20][0], L0[20][1], L0[20][2]},
        {L0[21][0], L0[21][1], L0[21][2]},
        {L0[22][0], L0[22][1], L0[22][2]},
        {L0[23][0], L0[23][1], L0[23][2]},
        {L0[24][0], L0[24][1], L0[24][2]},
        {L0[25][0], L0[25][1], L0[25][2]},
        {L0[26][0], L0[26][1], L0[26][2]},
        {L0[27][0], L0[27][1], L0[27][2]},
        {L0[28][0], L0[28][1], L0[28][2]},
        {L0[29][0], L0[29][1], L0[29][2]},
        {L0[30][0], L0[30][1], L0[30][2]},
        {L0[31][0], L0[31][1], L0[31][2]},
        {L0[32][0], L0[32][1], L0[32][2]},
        {L0[33][0], L0[33][1], L0[33][2]},
        {L0[34][0], L0[34][1], L0[34][2]},
        {L0[35][0], L0[35][1], L0[35][2]},
        {L0[36][0], L0[36][1], L0[36][2]},
        {L0[37][0], L0[37][1], L0[37][2]},
        {L0[38][0], L0[38][1], L0[38][2]},
        {L0[39][0], L0[39][1], L0[39][2]},
        {L0[40][0], L0[40][1], L0[40][2]},
        {L0[41][0], L0[41][1], L0[41][2]},
        {L0[42][0], L0[42][1], L0[42][2]},
        {L0[43][0], L0[43][1], L0[43][2]},
        {L0[44][0], L0[44][1], L0[44][2]},
        {L0[45][0], L0[45][1], L0[45][2]},
        {L0[46][0], L0[46][1], L0[46][2]},
        {L0[47][0], L0[47][1], L0[47][2]},
        {L0[48][0], L0[48][1], L0[48][2]},
        {L0[49][0], L0[49][1], L0[49][2]},
        {L0[50][0], L0[50][1], L0[50][2]},
        {L0[51][0], L0[51][1], L0[51][2]},
        {L0[52][0], L0[52][1], L0[52][2]},
        {L0[53][0], L0[53][1], L0[53][2]},
        {L0[54][0], L0[54][1], L0[54][2]},
        {L0[55][0], L0[55][1], L0[55][2]},
        {L0[56][0], L0[56][1], L0[56][2]},
        {L0[57][0], L0[57][1], L0[57][2]},
        {L0[58][0], L0[58][1], L0[58][2]},
        {L0[59][0], L0[59][1], L0[59][2]},
        {L0[60][0], L0[60][1], L0[60][2]},
        {L0[61][0], L0[61][1], L0[61][2]},
        {L0[62][0], L0[62][1], L0[62][2]},
        {L0[63][0], L0[63][1], L0[63][2]},
        {L0[64][0], L0[64][1], L0[64][2]},
        {L0[65][0], L0[65][1], L0[65][2]},
        {L0[66][0], L0[66][1], L0[66][2]},
        {L0[67][0], L0[67][1], L0[67][2]},
        {L0[68][0], L0[68][1], L0[68][2]},
        {L0[69][0], L0[69][1], L0[69][2]},
        {L0[70][0], L0[70][1], L0[70][2]},
        {L0[71][0], L0[71][1], L0[71][2]},
        {L0[72][0], L0[72][1], L0[72][2]},
        {L0[73][0], L0[73][1], L0[73][2]},
        {L0[74][0], L0[74][1], L0[74][2]},
        {L0[75][0], L0[75][1], L0[75][2]},
        {L0[76][0], L0[76][1], L0[76][2]},
        {L0[77][0], L0[77][1], L0[77][2]},
        {L0[78][0], L0[78][1], L0[78][2]},
        {L0[79][0], L0[79][1], L0[79][2]},
        {L0[80][0], L0[80][1], L0[80][2]},
        {L0[81][0], L0[81][1], L0[81][2]},
        {L0[82][0], L0[82][1], L0[82][2]},
        {L0[83][0], L0[83][1], L0[83][2]},
        {L0[84][0], L0[84][1], L0[84][2]},
        {L0[85][0], L0[85][1], L0[85][2]},
        {L0[86][0], L0[86][1], L0[86][2]},
        {L0[87][0], L0[87][1], L0[87][2]},
        {L0[88][0], L0[88][1], L0[88][2]},
        {L0[89][0], L0[89][1], L0[89][2]},
        {L0[90][0], L0[90][1], L0[90][2]},
        {L0[91][0], L0[91][1], L0[91][2]},
        {L0[92][0], L0[92][1], L0[92][2]},
        {L0[93][0], L0[93][1], L0[93][2]},
        {L0[94][0], L0[94][1], L0[94][2]},
        {L0[95][0], L0[95][1], L0[95][2]},
        {L0[96][0], L0[96][1], L0[96][2]},
        {L0[97][0], L0[97][1], L0[97][2]},
        {L0[98][0], L0[98][1], L0[98][2]},
        {L0[99][0], L0[99][1], L0[99][2]},
        {L0[100][0], L0[100][1], L0[100][2]},
        {L0[101][0], L0[101][1], L0[101][2]},
        {L0[102][0], L0[102][1], L0[102][2]},
        {L0[103][0], L0[103][1], L0[103][2]},
        {L0[104][0], L0[104][1], L0[104][2]},
        {L0[105][0], L0[105][1], L0[105][2]},
        {L0[106][0], L0[106][1], L0[106][2]},
        {L0[107][0], L0[107][1], L0[107][2]},
        {L0[108][0], L0[108][1], L0[108][2]},
        {L0[109][0], L0[109][1], L0[109][2]},
        {L0[110][0], L0[110][1], L0[110][2]},
        {L0[111][0], L0[111][1], L0[111][2]},
        {L0[112][0], L0[112][1], L0[112][2]},
        {L0[113][0], L0[113][1], L0[113][2]},
        {L0[114][0], L0[114][1], L0[114][2]},
        {L0[115][0], L0[115][1], L0[115][2]},
        {L0[116][0], L0[116][1], L0[116][2]},
        {L0[117][0], L0[117][1], L0[117][2]},
        {L0[118][0], L0[118][1], L0[118][2]},
        {L0[119][0], L0[119][1], L0[119][2]},
        {L0[120][0], L0[120][1], L0[120][2]},
        {L0[121][0], L0[121][1], L0[121][2]},
        {L0[122][0], L0[122][1], L0[122][2]},
        {L0[123][0], L0[123][1], L0[123][2]},
        {L0[124][0], L0[124][1], L0[124][2]},
        {L0[125][0], L0[125][1], L0[125][2]},
        {L0[126][0], L0[126][1], L0[126][2]},
        {L0[127][0], L0[127][1], L0[127][2]},
        {L0[128][0], L0[128][1], L0[128][2]},
        {L0[129][0], L0[129][1], L0[129][2]},
        {L0[130][0], L0[130][1], L0[130][2]},
        {L0[131][0], L0[131][1], L0[131][2]},
        {L0[132][0], L0[132][1], L0[132][2]},
        {L0[133][0], L0[133][1], L0[133][2]},
        {L0[134][0], L0[134][1], L0[134][2]},
        {L0[135][0], L0[135][1], L0[135][2]},
        {L0[136][0], L0[136][1], L0[136][2]},
        {L0[137][0], L0[137][1], L0[137][2]},
        {L0[138][0], L0[138][1], L0[138][2]},
        {L0[139][0], L0[139][1], L0[139][2]},
        {L0[140][0], L0[140][1], L0[140][2]},
        {L0[141][0], L0[141][1], L0[141][2]},
        {L0[142][0], L0[142][1], L0[142][2]},
        {L0[143][0], L0[143][1], L0[143][2]},
        {L0[144][0], L0[144][1], L0[144][2]},
        {L0[145][0], L0[145][1], L0[145][2]},
        {L0[146][0], L0[146][1], L0[146][2]},
        {L0[147][0], L0[147][1], L0[147][2]},
        {L0[148][0], L0[148][1], L0[148][2]},
        {L0[149][0], L0[149][1], L0[149][2]},
        {L0[150][0], L0[150][1], L0[150][2]},
        {L0[151][0], L0[151][1], L0[151][2]},
        {L0[152][0], L0[152][1], L0[152][2]},
        {L0[153][0], L0[153][1], L0[153][2]},
        {L0[154][0], L0[154][1], L0[154][2]},
        {L0[155][0], L0[155][1], L0[155][2]},
        {L0[156][0], L0[156][1], L0[156][2]},
        {L0[157][0], L0[157][1], L0[157][2]},
        {L0[158][0], L0[158][1], L0[158][2]},
        {L0[159][0], L0[159][1], L0[159][2]},
    };
    fprintf(stderr,
      "attempt %u: c0 was outside image(L0) (image_rank=%u direct_rank=%u)\n",
            attempt, rank, rank_bitset(direct));
    if (attempt == 1) {
      fprintf(stderr, "executed_map_ranks L0=%u L1=%u L2=%u L3=%u\n",
              executed_map_rank(L0), executed_map_rank(L1), executed_map_rank(L2),
              executed_map_rank(L3));
      fprintf(stderr, "C0=");
      for (unsigned int i = 0; i < BYTES; ++i) {
        fprintf(stderr, "%02x", mats.C0[i]);
      }
      fprintf(stderr, "\n");
      fprintf(stderr, "L0_MATRIX_BEGIN\n");
      for (unsigned int row = 0; row < CSP; ++row) {
        fprintf(stderr, "%016" PRIx64 "%016" PRIx64 "%016" PRIx64 "\n", L0[row][0],
                L0[row][1], L0[row][2]);
      }
      fprintf(stderr, "L0_MATRIX_END\n");
    }
    return 0;
  }

  bf160_t k = bf160_zero();
  BF_VALUE(k, 0) = k_words[0];
  BF_VALUE(k, 1) = k_words[1];
  BF_VALUE(k, 2) = k_words[2];
  const bf160_t s2_input = bf160_add(map_apply(L0, k), c0);
  if (!is_zero((const uint64_t[WORDS]){BF_VALUE(s2_input, 0), BF_VALUE(s2_input, 1),
                                       BF_VALUE(s2_input, 2)})) {
    fprintf(stderr, "attempt %u: failed to force S2 input to zero\n", attempt);
    return 0;
  }

  const bf160_t v1 = bf160_s1(bf160_add(k, c0));
  if (is_zero((const uint64_t[WORDS]){BF_VALUE(v1, 0), BF_VALUE(v1, 1), BF_VALUE(v1, 2)})) {
    return 0;
  }

  uint64_t t_columns[CSP][WORDS];
  uint64_t base[WORDS];
  make_t_columns(&mats, v1, k, t_columns, base);
  for (unsigned int col = 0; col < CSP; ++col) {
    for (unsigned int w = 0; w < WORDS; ++w) {
      t_columns[col][w] ^= base[w];
    }
  }
  uint64_t target[WORDS] = {BF_VALUE(t, 0), BF_VALUE(t, 1), BF_VALUE(t, 2)};
  for (unsigned int w = 0; w < WORDS; ++w) {
    target[w] ^= base[w];
  }

  uint64_t v2_words[WORDS] = {0};
  if (!solve_columns(t_columns, target, v2_words, &rank)) {
    fprintf(stderr, "attempt %u: public key skipped because T is singular (rank=%u)\n", attempt,
            rank);
    return 0;
  }

  bf160_t v2 = bf160_zero();
  BF_VALUE(v2, 0) = v2_words[0];
  BF_VALUE(v2, 1) = v2_words[1];
  BF_VALUE(v2, 2) = v2_words[2];

  const bf160_t tt =
      bf160_add(bf160_add(bf160_mul(map_apply(L1, v1), map_apply(L2, v2)),
                         map_apply(L3, bf160_add(k, bf160_add(v1, v2)))),
                t);
  const bf160_t s2_checked =
      bf160_add(bf160_add(bf160_mul(s2_input, v2), bf160_pow_67_minus_1(s2_input)), bf160_zero());
  if (!is_zero((const uint64_t[WORDS]){BF_VALUE(tt, 0), BF_VALUE(tt, 1), BF_VALUE(tt, 2)}) ||
      !is_zero((const uint64_t[WORDS]){BF_VALUE(s2_checked, 0), BF_VALUE(s2_checked, 1),
                                       BF_VALUE(s2_checked, 2)})) {
    fprintf(stderr, "attempt %u: reconstructed constraint check failed\n", attempt);
    return 0;
  }

  /*
   * The verifier never binds the signing randomness key passed to CoinHash.
   * Use an all-zero, publicly chosen key to avoid using the honest secret.
   */
  memset(forged_key, 0, BYTES);
  bf160_store(witness, k);
  bf160_store(witness + BYTES, v1);
  bf160_store(witness + 2 * BYTES, v2);
  voleith_sign(sig, msg, sizeof(msg) - 1, forged_key, pk, pk + BYTES, witness, rho, sizeof(rho),
               params);

  const int accepted = sig_verify(pk, pk_len, sig, sig_len, (unsigned char *)msg,
                                  (unsigned long long)(sizeof(msg) - 1));
  const bf160_t actual_v2 = bf160_s2(s2_input);
  const int actual_witness =
      memcmp(&actual_v2, &v2, sizeof(v2)) == 0;

  printf("attempt=%u\n", attempt);
  printf("s2_input_zero=1\n");
  printf("T_invertible=1\n");
  printf("quick_owl_residual_zero=1\n");
  printf("actual_lynx_witness=%d\n", actual_witness);
  printf("signature_verify_exit=%d\n", accepted);
  printf("pk=");
  for (unsigned int i = 0; i < 40; ++i) {
    printf("%02x", pk[i]);
  }
  printf("\nwitness=");
  for (unsigned int i = 0; i < 3 * BYTES; ++i) {
    printf("%02x", witness[i]);
  }
  printf("\n");

  *out_k = k;
  *out_v1 = v1;
  *out_v2 = v2;
  return accepted == 0;
}

int main(int argc, char **argv) {
  unsigned int attempts = 1;
  if (argc == 2) {
    attempts = (unsigned int)strtoul(argv[1], NULL, 10);
  }

  unsigned char seed[64];
  memset(seed, 0x5a, sizeof(seed));
  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
    fprintf(stderr, "init_random_number failed\n");
    return 2;
  }

  const sig_paramset_t *params = sig_get_paramset(LYNXER_160F);
  unsigned char pk[40] = {0};
  unsigned char sk[40] = {0};
  unsigned char sig[5801] = {0};
  unsigned char witness[60] = {0};
  unsigned char forged_key[20] = {0};
  bf160_t k;
  bf160_t v1;
  bf160_t v2;

  for (unsigned int attempt = 1; attempt <= attempts; ++attempt) {
    if (try_public_key(attempt, params, pk, sk, sig, witness, forged_key, &k, &v1, &v2)) {
      return 0;
    }
  }
  return 1;
}
