#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "parsing.h"

#include "loong_pke.c"

DRNG_ctx drng_algorithm;

static int solve_binary(unsigned long long *a, unsigned int rows,
                        unsigned int vars, unsigned int words,
                        unsigned char *out)
{
	unsigned int rank = 0;

	memset(out, 0, vars);
	for (unsigned int col = 0; col < vars; col++) {
		unsigned int pivot = rank;
		while (pivot < rows &&
		       ((a[pivot * words + col / 64] >> (col % 64)) & 1ULL) == 0) {
			pivot++;
		}
		if (pivot == rows) {
			continue;
		}
		if (pivot != rank) {
			for (unsigned int j = 0; j < words; j++) {
				unsigned long long t = a[pivot * words + j];
				a[pivot * words + j] = a[rank * words + j];
				a[rank * words + j] = t;
			}
		}
		for (unsigned int row = rank + 1; row < rows; row++) {
			if (((a[row * words + col / 64] >> (col % 64)) & 1ULL) != 0) {
				for (unsigned int j = 0; j < words; j++) {
					a[row * words + j] ^= a[rank * words + j];
				}
			}
		}
		rank++;
	}
	for (unsigned int row = rank; row < rows; row++) {
		unsigned int nonzero = 0;
		unsigned int rhs =
			(unsigned int)((a[row * words + words - 1] >> 63) & 1ULL);
		for (unsigned int col = 0; col < vars; col++) {
			if (((a[row * words + col / 64] >> (col % 64)) & 1ULL) != 0) {
				nonzero = 1;
				break;
			}
		}
		if (!nonzero && rhs) {
			return -1;
		}
	}
	for (int r = (int)rank - 1; r >= 0; r--) {
		unsigned int p = (unsigned int)r;
		unsigned int lead = 0;
		while (lead < vars &&
		       ((a[p * words + lead / 64] >> (lead % 64)) & 1ULL) == 0) {
			lead++;
		}
		unsigned int rhs =
			(unsigned int)((a[p * words + words - 1] >> 63) & 1ULL);
		for (unsigned int col = lead + 1; col < vars; col++) {
			if (((a[p * words + col / 64] >> (col % 64)) & 1ULL) != 0 &&
			    out[col] != 0) {
				rhs ^= 1U;
			}
		}
		out[lead] = (unsigned char)rhs;
	}
	return 0;
}

int main(int argc, char **argv)
{
	const unsigned int rx = LOONG_AXY_00;
	const unsigned int ry = LOONG_AXY_11;
	const unsigned int g = LOONG_AXY_01;
	const unsigned int vars = LOONG_N * (rx + ry);
	const unsigned int words = (vars + 64U) / 64U;
	const unsigned int rows = LOONG_N * LOONG_M;
	const unsigned int x_size = LOONG_N * LOONG_N1;
	unsigned long long trials = argc > 1 ? strtoull(argv[1], 0, 10) : 10;
	unsigned char seed[64];
	unsigned char *pk = calloc(LOONG_PK_BYTES, 1);
	unsigned char *sk = calloc(LOONG_SK_PRIME_BYTES, 1);
	rbc_elt *public_g = calloc(LOONG_N1 * LOONG_N2, sizeof(*public_g));
	rbc_elt *h = calloc(LOONG_N * LOONG_N, sizeof(*h));
	rbc_elt *expected = calloc(x_size, sizeof(*expected));
	rbc_elt *recovered = calloc(x_size, sizeof(*recovered));
	unsigned long long failures = 0;

	for (unsigned int i = 0; i < sizeof(seed); i++) {
		seed[i] = (unsigned char)(i * 29U + 7U);
	}
	init_random_number(&drng_algorithm, seed, sizeof(seed) * 8ULL);
	if (pk == 0 || sk == 0 || public_g == 0 || h == 0 ||
	    expected == 0 || recovered == 0) {
		return 2;
	}
	for (unsigned long long t = 0; t < trials; t++) {
		unsigned char public_seed[LOONG_PK_SEED_BYTES];
		unsigned char keygen_seed[LOONG_PK_SEED_BYTES];
		loong_public_key_view pv;
		int rc;

		get_random_number(&drng_algorithm, public_seed, sizeof(public_seed) * 8ULL);
		get_random_number(&drng_algorithm, keygen_seed, sizeof(keygen_seed) * 8ULL);
		rc = loong_pke_keygen_derandomized(
			pk, LOONG_PK_BYTES, sk, LOONG_SK_PRIME_BYTES,
			public_seed, sizeof(public_seed), keygen_seed, sizeof(keygen_seed));
		if (rc == 0) {
			rc = loong_public_key_parse(&pv, pk, LOONG_PK_BYTES);
		}
		if (rc == 0) {
			rc = generate_public_objects(public_g, h, pv.seed, pv.seed_len_bytes);
		}
		if (rc == 0) {
			rc = logical_vec_decode(expected, x_size,
			                        sk + LOONG_SK_X_OFFSET, LOONG_X_OR_S_BYTES);
		}
		if (rc != 0) {
			printf("trial=%llu setup_fail=%d\n", t, rc);
			failures++;
			continue;
		}
		memset(recovered, 0, x_size * sizeof(*recovered));
		for (unsigned int col = 0; col < LOONG_N1; col++) {
			unsigned long long *eq =
				calloc((size_t)rows * words, sizeof(*eq));
			unsigned char *sol = calloc(vars, 1);
			if (eq == 0 || sol == 0) {
				return 2;
			}
			for (unsigned int row = 0; row < LOONG_N; row++) {
				for (unsigned int c = 0; c < LOONG_M; c++) {
					unsigned int e = row * LOONG_M + c;
					for (unsigned int k = 0; k < LOONG_N; k++) {
						for (unsigned int i = 0; i < rx; i++) {
							rbc_elt basis, product;
							rbc_elt_set_zero(&basis);
							rbc_elt_set_coefficient(&basis, i, 1);
							rbc_elt_mul(&product, &h[row * LOONG_N + k],
							            &basis);
							if (rbc_elt_get_coefficient(&product, c) != 0) {
								unsigned int u = k * rx + i;
								eq[e * words + u / 64] ^= 1ULL << (u % 64);
							}
						}
					}
					for (unsigned int i = 0; i < ry; i++) {
						unsigned int exponent = i < g ? i : rx + i - g;
						if (c == exponent) {
							unsigned int u = LOONG_N * rx + row * ry + i;
							eq[e * words + u / 64] ^= 1ULL << (u % 64);
						}
					}
					{
						unsigned long long bp =
							((unsigned long long)row * LOONG_N1 + col) *
								LOONG_M + c;
						unsigned int bit =
							(pv.s[bp / 8] >> (7U - (bp % 8U))) & 1U;
						if (bit != 0) {
							eq[e * words + words - 1] ^= 1ULL << 63;
						}
					}
				}
			}
			if (solve_binary(eq, rows, vars, words, sol) != 0) {
				printf("trial=%llu col=%u inconsistent\n", t, col);
				failures++;
				free(eq);
				free(sol);
				continue;
			}
			for (unsigned int row = 0; row < LOONG_N; row++) {
				rbc_elt v;
				rbc_elt_set_zero(&v);
				for (unsigned int i = 0; i < rx; i++) {
					if (sol[row * rx + i] != 0) {
						rbc_elt bit;
						rbc_elt_set_zero(&bit);
						rbc_elt_set_coefficient(&bit, i, 1);
						rbc_elt_add(&v, &v, &bit);
					}
				}
				rbc_elt_set(&recovered[row * LOONG_N1 + col], &v);
			}
			free(eq);
			free(sol);
		}
		{
			unsigned int all_equal = 1;
			for (unsigned int i = 0; i < x_size; i++) {
				if (!rbc_elt_equal(&recovered[i], &expected[i])) {
					all_equal = 0;
					break;
				}
			}
			if (!all_equal) {
				failures++;
			}
			printf("trial=%llu vars=%u rows=%u recovered_all_X=%u\n",
			       t, vars, rows, all_equal);
		}
	}
	printf("instance=%s trials=%llu failures=%llu\n",
	       LOONG_INSTANCE_NAME, trials, failures);
	return failures == 0 ? 0 : 1;
}
