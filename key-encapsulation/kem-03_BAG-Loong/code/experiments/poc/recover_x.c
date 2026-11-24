#include "loong_hash.h"
#include "loong_kem.h"
#include "loong_parameters.h"
#include "loong_pke.h"
#include "loong_status.h"
#include "loong_xof_reader.h"
#include "parsing.h"
#include "rbc_elt.h"
#include "rbc_vec.h"
#include "drng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PKE_L ((unsigned int)(LOONG_N1 * LOONG_N2))
#define XS_SIZE ((unsigned int)(LOONG_N * LOONG_N1))
#define ELT_BYTES ((unsigned int)((LOONG_M + 7U) / 8U))
#define G_ATTEMPTS 1024U
#define UNION_RANK ((unsigned int)(LOONG_AXY_00 + LOONG_AXY_11 - LOONG_AXY_01))

DRNG_ctx drng_algorithm;

static int read_random_elt(rbc_elt *e, loong_xof_reader *reader)
{
	unsigned char bytes[16];
	unsigned int i;
	int status;

	if (ELT_BYTES > sizeof(bytes)) {
		return LOONG_ERR_OVERFLOW;
	}
	status = loong_xof_reader_read(bytes, ELT_BYTES, reader);
	if (status != LOONG_SUCCESS) {
		return status;
	}
	rbc_elt_set_zero(e);
	for (i = 0; i < LOONG_M; i++) {
		unsigned int bit =
		    (unsigned int)((bytes[i / 8U] >> (i % 8U)) & 1U);
		if (rbc_elt_set_coefficient(e, i, bit) != 0) {
			return LOONG_ERR_BAD_LENGTH;
		}
	}
	return LOONG_SUCCESS;
}

/*
 * Recreate the public H matrix exactly as generate_public_objects() does.
 * Only the public key seed is used.
 */
static int expand_public_h(rbc_elt *h, const unsigned char *seed,
                           unsigned long long seed_len)
{
	unsigned char *buffer = NULL;
	loong_xof_reader reader;
	rbc_elt *g = NULL;
	unsigned long long g_budget;
	unsigned long long h_bytes;
	unsigned long long budget;
	unsigned int attempt;
	unsigned int i;
	int status = LOONG_ERR_ALLOC;

	g_budget = (unsigned long long)LOONG_N_PRIME * ELT_BYTES * G_ATTEMPTS;
	h_bytes = (unsigned long long)LOONG_N * LOONG_N * ELT_BYTES;
	budget = g_budget + h_bytes;
	buffer = (unsigned char *)malloc((size_t)budget);
	g = (rbc_elt *)calloc(PKE_L, sizeof(*g));
	if (buffer == NULL || g == NULL) {
		goto cleanup;
	}
	status = loong_xof_expand_public_seed(buffer, budget * 8ULL, seed,
	                                      seed_len);
	if (status != LOONG_SUCCESS) {
		goto cleanup;
	}
	loong_xof_reader_init(&reader, buffer, budget);

	for (attempt = 0; attempt < G_ATTEMPTS; attempt++) {
		unsigned int rank = 0;
		for (i = 0; i < LOONG_N_PRIME; i++) {
			status = read_random_elt(&g[i], &reader);
			if (status != LOONG_SUCCESS) {
				goto cleanup;
			}
		}
		if (rbc_vec_get_rank(&rank, g, LOONG_N_PRIME) != 0) {
			status = LOONG_ERR_BAD_LENGTH;
			goto cleanup;
		}
		if (rank == LOONG_N_PRIME) {
			break;
		}
	}
	if (attempt == G_ATTEMPTS) {
		status = LOONG_ERR_SAMPLING;
		goto cleanup;
	}
	for (i = 0; i < (unsigned int)(LOONG_N * LOONG_N); i++) {
		status = read_random_elt(&h[i], &reader);
		if (status != LOONG_SUCCESS) {
			goto cleanup;
		}
	}
	status = LOONG_SUCCESS;

cleanup:
	free(buffer);
	free(g);
	return status;
}

static int decode_logical_vec(rbc_elt *v, unsigned int size,
                              const unsigned char *in)
{
	unsigned int i;
	unsigned int j;
	unsigned long long bit_pos = 0;

	rbc_vec_set_zero(v, size);
	for (i = 0; i < size; i++) {
		for (j = 0; j < LOONG_M; j++) {
			unsigned int bit;
			unsigned long long byte_pos = bit_pos / 8ULL;
			unsigned int bit_in_byte = (unsigned int)(bit_pos % 8ULL);
			bit = (unsigned int)((in[byte_pos] >> (7U - bit_in_byte)) &
			                     1U);
			if (rbc_elt_set_coefficient(&v[i], j, bit) != 0) {
				return LOONG_ERR_BAD_LENGTH;
			}
			bit_pos++;
		}
	}
	return LOONG_SUCCESS;
}

static int encode_logical_vec(unsigned char *out, unsigned long long out_len,
                              const rbc_elt *v, unsigned int size)
{
	unsigned int i;
	unsigned int j;
	unsigned long long bit_pos = 0;

	memset(out, 0, (size_t)out_len);
	for (i = 0; i < size; i++) {
		for (j = 0; j < LOONG_M; j++) {
			if (rbc_elt_get_coefficient(&v[i], j) != 0) {
				unsigned long long byte_pos = bit_pos / 8ULL;
				unsigned int bit_in_byte =
				    (unsigned int)(bit_pos % 8ULL);
				out[byte_pos] |=
				    (unsigned char)(1U << (7U - bit_in_byte));
			}
			bit_pos++;
		}
	}
	return LOONG_SUCCESS;
}

/*
 * Solve A*X=B over F_{2^m} by Gauss-Jordan elimination. The augmented
 * matrix has LOONG_AXY_00 right-hand-side columns.
 */
static int solve_over_field(rbc_elt *x, const rbc_elt *h, const rbc_elt *s)
{
	const unsigned int n = LOONG_N;
	const unsigned int n1 = LOONG_N1;
	const unsigned int rows = UNION_RANK;
	const unsigned int a = LOONG_AXY_00;
	const unsigned int width = a + n1;
	rbc_elt *aug;
	unsigned int col;
	unsigned int i;
	unsigned int j;

	aug = (rbc_elt *)calloc((size_t)a * width, sizeof(*aug));
	if (aug == NULL) {
		return LOONG_ERR_ALLOC;
	}
	for (i = 0; i < a; i++) {
		for (j = 0; j < a; j++) {
			rbc_elt_set(&aug[i * width + j],
			            &h[(rows + i) * n + j]);
		}
		for (j = 0; j < n1; j++) {
			rbc_elt_set(&aug[i * width + a + j],
			            &s[(rows + i) * n1 + j]);
		}
	}

	for (col = 0; col < a; col++) {
		unsigned int pivot = col;
		rbc_elt pivot_inv;
		while (pivot < a && rbc_elt_is_zero(&aug[pivot * width + col])) {
			pivot++;
		}
		if (pivot == a) {
			free(aug);
			return LOONG_ERR_SAMPLING;
		}
		if (pivot != col) {
			for (j = 0; j < width; j++) {
				rbc_elt tmp;
				rbc_elt_set(&tmp, &aug[col * width + j]);
				rbc_elt_set(&aug[col * width + j],
				            &aug[pivot * width + j]);
				rbc_elt_set(&aug[pivot * width + j], &tmp);
			}
		}
		if (rbc_elt_inv(&pivot_inv, &aug[col * width + col]) != 0) {
			free(aug);
			return LOONG_ERR_SAMPLING;
		}
		for (j = 0; j < width; j++) {
			rbc_elt tmp;
			rbc_elt_mul(&tmp, &aug[col * width + j], &pivot_inv);
			rbc_elt_set(&aug[col * width + j], &tmp);
		}
		for (i = 0; i < a; i++) {
			rbc_elt factor;
			if (i == col || rbc_elt_is_zero(&aug[i * width + col])) {
				continue;
			}
			rbc_elt_set(&factor, &aug[i * width + col]);
			for (j = 0; j < width; j++) {
				rbc_elt term;
				rbc_elt_mul(&term, &factor, &aug[col * width + j]);
				rbc_elt_add(&aug[i * width + j],
				            &aug[i * width + j], &term);
			}
		}
	}

	rbc_vec_set_zero(x, XS_SIZE);
	for (i = 0; i < a; i++) {
		for (j = 0; j < n1; j++) {
			rbc_elt_set(&x[i * n1 + j], &aug[i * width + a + j]);
		}
	}
	free(aug);
	return LOONG_SUCCESS;
}

static void xor_word_row(unsigned long long *dst, const unsigned long long *src,
                         unsigned int words)
{
	unsigned int i;
	for (i = 0; i < words; i++) {
		dst[i] ^= src[i];
	}
}

static void set_bit(unsigned long long *row, unsigned int position)
{
	row[position / 64U] |= 1ULL << (position % 64U);
}

static unsigned int get_bit(const unsigned long long *row,
                            unsigned int position)
{
	return (unsigned int)((row[position / 64U] >> (position % 64U)) & 1ULL);
}

/*
 * The reference support sampler ignores the XOF and always selects
 * U=span(e_0,...,e_{a-1}) and V=span(e_0,...,e_{inter-1},e_a,...).
 * Project every equation onto coordinates outside V. Y vanishes there,
 * leaving a binary linear system for all coefficients of X.
 */
static int solve_from_fixed_supports(rbc_elt *x, const rbc_elt *h,
                                     const rbc_elt *s)
{
	const unsigned int n = LOONG_N;
	const unsigned int n1 = LOONG_N1;
	const unsigned int a = LOONG_AXY_00;
	const unsigned int b = LOONG_AXY_11;
	const unsigned int inter = LOONG_AXY_01;
	const unsigned int vars = n * a;
	unsigned int outside[128];
	unsigned int outside_count = 0;
	const unsigned int words = (vars + 1U + 63U) / 64U;
	unsigned long long *rows;
	rbc_elt u[8];
	unsigned int vpos[8];
	unsigned int eqs;
	unsigned int jcol;
	unsigned int i;
	unsigned int k;
	unsigned int r;
	unsigned int p;
	unsigned int col;
	unsigned int rank = 0;

	if (a > 8U || b > 8U || inter > b) {
		return LOONG_ERR_OVERFLOW;
	}
	rows = (unsigned long long *)calloc((size_t)eqs * words,
	                                    sizeof(*rows));
	if (rows == NULL) {
		return LOONG_ERR_ALLOC;
	}
	for (r = 0; r < a; r++) {
		rbc_elt_set_zero(&u[r]);
		if (rbc_elt_set_coefficient(&u[r], r, 1U) != 0) {
			free(rows);
			return LOONG_ERR_BAD_LENGTH;
		}
	}
	for (r = 0; r < b; r++) {
		vpos[r] = r < inter ? r : a + (r - inter);
	}
	for (p = 0; p < LOONG_M; p++) {
		unsigned int in_v = 0;
		for (r = 0; r < b; r++) {
			if (vpos[r] == p) {
				in_v = 1;
				break;
			}
		}
		if (!in_v) {
			outside[outside_count++] = p;
		}
	}
	eqs = n * outside_count;
	free(rows);
	rows = (unsigned long long *)calloc((size_t)eqs * words,
	                                    sizeof(*rows));
	if (rows == NULL) {
		return LOONG_ERR_ALLOC;
	}

	for (jcol = 0; jcol < n1; jcol++) {
		rank = 0;
		memset(rows, 0, (size_t)eqs * words * sizeof(*rows));
		for (i = 0; i < n; i++) {
			for (k = 0; k < n; k++) {
				for (r = 0; r < a; r++) {
					rbc_elt product;
					unsigned int var = k * a + r;
					rbc_elt_mul(&product, &h[i * n + k], &u[r]);
					for (p = 0; p < outside_count; p++) {
						if (rbc_elt_get_coefficient(
						        &product, outside[p]) !=
						    0) {
							set_bit(&rows[(i * outside_count + p) *
							              words],
							        var);
						}
					}
				}
			}
			for (p = 0; p < outside_count; p++) {
				if (rbc_elt_get_coefficient(
				        &s[i * n1 + jcol], outside[p]) != 0) {
					set_bit(&rows[(i * outside_count + p) * words],
					        vars);
				}
			}
		}

		for (col = 0; col < vars; col++) {
			unsigned int pivot = rank;
			while (pivot < eqs && get_bit(&rows[pivot * words], col) == 0) {
				pivot++;
			}
			if (pivot == eqs) {
				continue;
			}
			if (pivot != rank) {
				for (p = 0; p < words; p++) {
					unsigned long long tmp =
					    rows[rank * words + p];
					rows[rank * words + p] =
					    rows[pivot * words + p];
					rows[pivot * words + p] = tmp;
				}
			}
			for (i = 0; i < eqs; i++) {
				if (i != rank && get_bit(&rows[i * words], col) != 0) {
					xor_word_row(&rows[i * words],
					             &rows[rank * words], words);
				}
			}
			rank++;
		}
		if (rank != vars) {
			free(rows);
			return LOONG_ERR_SAMPLING;
		}
		for (i = rank; i < eqs; i++) {
			if (get_bit(&rows[i * words], vars) != 0) {
				free(rows);
				return LOONG_ERR_SAMPLING;
			}
		}
		for (k = 0; k < n; k++) {
			rbc_elt value;
			rbc_elt_set_zero(&value);
			for (r = 0; r < a; r++) {
				if (get_bit(&rows[(k * a + r) * words], vars) != 0) {
					rbc_elt_add(&value, &value, &u[r]);
				}
			}
			rbc_elt_set(&x[k * n1 + jcol], &value);
		}
	}
	free(rows);
	return LOONG_SUCCESS;
}

static int derive_g(unsigned char g[LOONG_G_BYTES], const unsigned char *pk,
                    const unsigned char *m, const unsigned char *salt)
{
	unsigned char id[LOONG_ID_BYTES];
	int status = loong_hash_id(id, pk, LOONG_PK_BYTES);

	if (status == LOONG_SUCCESS) {
		status = loong_hash_g(g, id, sizeof(id), m,
		                      loong_pke_get_message_len_bytes(), salt,
		                      LOONG_SALT_BYTES);
	}
	return status;
}

static int read_fixed_file(const char *path, unsigned char *out,
                           size_t expected)
{
	FILE *file = fopen(path, "rb");
	unsigned char extra;
	size_t got;

	if (file == NULL) {
		return 0;
	}
	got = fread(out, 1, expected, file);
	if (got != expected || fread(&extra, 1, 1, file) != 0) {
		fclose(file);
		return 0;
	}
	fclose(file);
	return 1;
}

int main(int argc, char **argv)
{
	unsigned char pk[LOONG_PK_BYTES];
	unsigned char sk[LOONG_SK_BYTES];
	unsigned char ss[LOONG_SS_BYTES];
	unsigned char recovered_ss[LOONG_SS_BYTES];
	unsigned char ct[LOONG_CT_BYTES];
	unsigned char recovered_ct[LOONG_PKE_CT_BYTES];
	unsigned char sk_prime[LOONG_SK_PRIME_BYTES];
	unsigned char recovered_x_bytes[LOONG_X_OR_S_BYTES];
	unsigned char recovered_message[(LOONG_K * LOONG_M + 7) / 8];
	unsigned char g[LOONG_G_BYTES];
	loong_public_key_view pk_view;
	loong_secret_key_view sk_view;
	rbc_elt *h = NULL;
	rbc_elt *s = NULL;
	rbc_elt *x = NULL;
	rbc_elt *true_x = NULL;
	int x_match = 0;
	int decrypt_match = 0;
	int kdf_match = 0;
	int status = 1;
	unsigned char drng_seed[64];
	unsigned long trial =
	    argc > 1 ? strtoul(argv[1], NULL, 0) : 0UL;
	int use_kat_files = argc == 6 && strcmp(argv[1], "kat") == 0;

	memset(pk, 0, sizeof(pk));
	memset(sk, 0, sizeof(sk));
	memset(ss, 0, sizeof(ss));
	memset(ct, 0, sizeof(ct));
	if (use_kat_files) {
		if (!read_fixed_file(argv[2], pk, sizeof(pk)) ||
		    !read_fixed_file(argv[3], sk, sizeof(sk)) ||
		    !read_fixed_file(argv[4], ct, sizeof(ct)) ||
		    !read_fixed_file(argv[5], ss, sizeof(ss))) {
			fprintf(stderr, "failed to read KAT files\n");
			return 1;
		}
	} else {
		for (size_t i = 0; i < sizeof(drng_seed); i++) {
			drng_seed[i] = (unsigned char)(
			    (trial * 131UL + i * 17UL + 29UL) & 0xffU);
		}
		if (init_random_number(&drng_algorithm, drng_seed,
		                       sizeof(drng_seed)) != 0) {
			fprintf(stderr, "DRNG initialization failed\n");
			return 1;
		}
		if (loong_kem_keygen(pk, sizeof(pk), sk, sizeof(sk)) !=
		    LOONG_SUCCESS) {
			fprintf(stderr, "keygen failed\n");
			goto cleanup;
		}
		if (loong_kem_encapsulate(pk, sizeof(pk), ss, sizeof(ss), ct,
		                          sizeof(ct)) != LOONG_SUCCESS) {
			fprintf(stderr, "encapsulation failed\n");
			goto cleanup;
		}
	}
	if (loong_public_key_parse(&pk_view, pk, sizeof(pk)) != LOONG_SUCCESS ||
	    loong_secret_key_parse(&sk_view, sk, sizeof(sk)) != LOONG_SUCCESS) {
		fprintf(stderr, "parse failed\n");
		goto cleanup;
	}
	{
		unsigned char sk_ss[LOONG_SS_BYTES];
		int sk_status =
		    loong_kem_decapsulate(sk, sizeof(sk), ct, sizeof(ct), sk_ss,
		                          sizeof(sk_ss));
		printf("original_decaps_status=%d shared_match=%d\n", sk_status,
		       memcmp(sk_ss, ss, sizeof(ss)) == 0);
	}

	h = (rbc_elt *)calloc((size_t)LOONG_N * LOONG_N, sizeof(*h));
	s = (rbc_elt *)calloc(XS_SIZE, sizeof(*s));
	x = (rbc_elt *)calloc(XS_SIZE, sizeof(*x));
	true_x = (rbc_elt *)calloc(XS_SIZE, sizeof(*true_x));
	if (h == NULL || s == NULL || x == NULL || true_x == NULL) {
		fprintf(stderr, "allocation failed\n");
		goto cleanup;
	}
	if (expand_public_h(h, pk_view.seed, pk_view.seed_len_bytes) !=
	    LOONG_SUCCESS) {
		fprintf(stderr, "public H expansion failed\n");
		goto cleanup;
	}
	if (decode_logical_vec(s, XS_SIZE, pk_view.s) != LOONG_SUCCESS ||
	    decode_logical_vec(true_x, XS_SIZE, sk_view.x) != LOONG_SUCCESS) {
		fprintf(stderr, "vector decode failed\n");
		goto cleanup;
	}
	if (solve_from_fixed_supports(x, h, s) != LOONG_SUCCESS) {
		fprintf(stderr, "fixed-support binary recovery failed\n");
		goto cleanup;
	}
	x_match = rbc_vec_equal(x, true_x, XS_SIZE);
	printf("recovery_x_match_before_decrypt=%d\n", x_match);

	memcpy(sk_prime, pk_view.seed, LOONG_PK_SEED_BYTES);
	encode_logical_vec(recovered_x_bytes, sizeof(recovered_x_bytes), x,
	                   XS_SIZE);
	memcpy(sk_prime + LOONG_PK_SEED_BYTES, recovered_x_bytes,
	       sizeof(recovered_x_bytes));
	{
		unsigned char original_message[sizeof(recovered_message)];
		int original_decrypt_status =
		    loong_pke_decrypt(original_message, sizeof(original_message),
		                      sk, LOONG_SK_PRIME_BYTES, ct,
		                      LOONG_PKE_CT_BYTES);
		int decrypt_status =
		    loong_pke_decrypt(recovered_message, sizeof(recovered_message),
		                      sk_prime, sizeof(sk_prime), ct,
		                      LOONG_PKE_CT_BYTES);
		printf("original_x_bytes_match=%d skprime_seed_match=%d "
		       "original_decrypt_status=%d recovered_decrypt_status=%d "
		       "plaintext_match=%d\n",
		       memcmp(recovered_x_bytes, sk_view.x,
		              sizeof(recovered_x_bytes)) == 0,
		       memcmp(sk_prime, sk, sizeof(sk_prime)) == 0,
		       original_decrypt_status, decrypt_status,
		       original_decrypt_status == LOONG_SUCCESS &&
		           memcmp(original_message, recovered_message,
		                  sizeof(recovered_message)) == 0);
		if (decrypt_status != LOONG_SUCCESS) {
			fprintf(stderr, "decrypt under recovered X failed\n");
			decrypt_match = 0;
			kdf_match = 0;
			status = 1;
			goto report;
		}
	}
	if (derive_g(g, pk, recovered_message, ct + LOONG_PKE_CT_BYTES) !=
	    LOONG_SUCCESS) {
		fprintf(stderr, "G derivation failed\n");
		goto cleanup;
	}
	if (loong_pke_encrypt_derandomized(
	        recovered_ct, sizeof(recovered_ct), pk, sizeof(pk),
	        recovered_message, sizeof(recovered_message), g, sizeof(g)) !=
	    LOONG_SUCCESS) {
		fprintf(stderr, "re-encryption failed\n");
		goto cleanup;
	}
	decrypt_match = memcmp(recovered_ct, ct, LOONG_PKE_CT_BYTES) == 0;
	if (loong_hash_kdf(recovered_ss, sizeof(recovered_ss), g, sizeof(g),
	                   recovered_ct, sizeof(recovered_ct)) != LOONG_SUCCESS) {
		fprintf(stderr, "KDF failed\n");
		goto cleanup;
	}
	kdf_match = memcmp(recovered_ss, ss, sizeof(ss)) == 0;

report:
	printf("trial=%lu instance=%s n=%d m=%d n1=%d X_support=%d union=%d\n",
	       trial,
	       LOONG_INSTANCE_NAME, LOONG_N, LOONG_M, LOONG_N1, LOONG_AXY_00,
	       UNION_RANK);
	printf("equations_per_column=%d unknown_bits_per_column=%d "
	       "columns=%d union_rank=%d\n",
	       LOONG_N * (LOONG_M - LOONG_AXY_11), LOONG_N * LOONG_AXY_00,
	       LOONG_N1, UNION_RANK);
	printf("X_match=%d decrypt_reenencrypt_match=%d session_key_match=%d\n",
	       x_match, decrypt_match, kdf_match);
	status = (x_match && decrypt_match && kdf_match) ? 0 : 1;

cleanup:
	free(h);
	free(s);
	free(x);
	free(true_x);
	return status;
}
