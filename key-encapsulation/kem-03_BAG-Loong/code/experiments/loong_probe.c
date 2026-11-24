#include "loong_pke.c"
#include "drng.h"

#include <stdio.h>

DRNG_ctx drng_algorithm;

static int write_exact(const char *path, const void *data, size_t n)
{
	FILE *f = fopen(path, "wb");
	if (f == NULL) {
		return -1;
	}
	if (fwrite(data, 1, n, f) != n) {
		fclose(f);
		return -1;
	}
	return fclose(f);
}

int main(int argc, char **argv)
{
	unsigned char public_seed[LOONG_PK_SEED_BYTES];
	unsigned char keygen_seed[LOONG_PK_SEED_BYTES];
	unsigned char pk[LOONG_PK_BYTES];
	unsigned char sk_prime[LOONG_SK_PRIME_BYTES];
	rbc_elt *g;
	rbc_elt *h;
	rbc_elt *x;
	rbc_elt *s;
	rbc_elt *hx;
	rbc_elt *y;
	loong_public_key_view pk_view;
	unsigned int i;
	int status;
	char path[512];

	if (argc != 2) {
		fprintf(stderr, "usage: %s OUTPUT_PREFIX\n", argv[0]);
		return 2;
	}
	for (i = 0; i < LOONG_PK_SEED_BYTES; i++) {
		public_seed[i] = (unsigned char)i;
		keygen_seed[i] = (unsigned char)(0x80U + i);
	}
	status = loong_pke_keygen_derandomized(
		pk, sizeof(pk), sk_prime, sizeof(sk_prime),
		public_seed, sizeof(public_seed),
		keygen_seed, sizeof(keygen_seed));
	if (status != LOONG_SUCCESS) {
		fprintf(stderr, "keygen status=%d\n", status);
		return 1;
	}

	g = (rbc_elt *)calloc((size_t)LOONG_PKE_L, sizeof(*g));
	h = (rbc_elt *)calloc((size_t)LOONG_N * LOONG_N, sizeof(*h));
	x = (rbc_elt *)calloc((size_t)LOONG_PKE_XS_SIZE, sizeof(*x));
	s = (rbc_elt *)calloc((size_t)LOONG_PKE_XS_SIZE, sizeof(*s));
	hx = (rbc_elt *)calloc((size_t)LOONG_PKE_XS_SIZE, sizeof(*hx));
	y = (rbc_elt *)calloc((size_t)LOONG_PKE_XS_SIZE, sizeof(*y));
	if (g == NULL || h == NULL || x == NULL || s == NULL ||
	    hx == NULL || y == NULL) {
		return 1;
	}
	status = generate_public_objects(g, h, public_seed, sizeof(public_seed));
	if (status != LOONG_SUCCESS) {
		fprintf(stderr, "public generation status=%d\n", status);
		return 1;
	}

	snprintf(path, sizeof(path), "%s.pk", argv[1]);
	if (write_exact(path, pk, sizeof(pk)) != 0) {
		return 1;
	}
	snprintf(path, sizeof(path), "%s.sk", argv[1]);
	if (write_exact(path, sk_prime, sizeof(sk_prime)) != 0) {
		return 1;
	}
	snprintf(path, sizeof(path), "%s.h", argv[1]);
	if (write_exact(path, h, (size_t)LOONG_N * LOONG_N * sizeof(*h)) != 0) {
		return 1;
	}
	if (loong_public_key_parse(&pk_view, pk, sizeof(pk)) != LOONG_SUCCESS ||
	    logical_vec_decode(x, LOONG_PKE_XS_SIZE,
	                       sk_prime + LOONG_SK_X_OFFSET,
	                       LOONG_X_OR_S_BYTES) != LOONG_SUCCESS ||
	    logical_vec_decode(s, LOONG_PKE_XS_SIZE,
	                       pk_view.s, pk_view.s_len_bytes) != LOONG_SUCCESS) {
		return 1;
	}
	matrix_mul(hx, h, LOONG_N, LOONG_N, x, LOONG_N1);
	for (i = 0; i < (unsigned int)LOONG_PKE_XS_SIZE; i++) {
		rbc_elt_add(&y[i], &s[i], &hx[i]);
	}
	snprintf(path, sizeof(path), "%s.x", argv[1]);
	if (write_exact(path, x, (size_t)LOONG_PKE_XS_SIZE * sizeof(*x)) != 0) {
		return 1;
	}
	snprintf(path, sizeof(path), "%s.s", argv[1]);
	if (write_exact(path, s, (size_t)LOONG_PKE_XS_SIZE * sizeof(*s)) != 0) {
		return 1;
	}
	snprintf(path, sizeof(path), "%s.y", argv[1]);
	if (write_exact(path, y, (size_t)LOONG_PKE_XS_SIZE * sizeof(*y)) != 0) {
		return 1;
	}
	free(g);
	free(h);
	free(x);
	free(s);
	free(hx);
	free(y);
	return 0;
}
