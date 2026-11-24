#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static uint32_t state = 0x12345678U;

static uint32_t next_u32(void)
{
	state ^= state << 13;
	state ^= state >> 17;
	state ^= state << 5;
	return state;
}

static void fill(unsigned char *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; ++i) {
		p[i] = (unsigned char)next_u32();
	}
}

int main(void)
{
	const unsigned long long pk_len = kem_get_pk_len_bytes();
	const unsigned long long sk_len = kem_get_sk_len_bytes();
	const unsigned long long ct_len = kem_get_ct_len_bytes();
	const unsigned long long ss_len = kem_get_ss_len_bytes();
	unsigned char *pk = calloc(1, (size_t)pk_len);
	unsigned char *sk = calloc(1, (size_t)sk_len);
	unsigned char *ct = calloc(1, (size_t)ct_len);
	unsigned char *ss = calloc(1, (size_t)ss_len);
	unsigned char seed[64];
	size_t i;

	if (!pk || !sk || !ct || !ss) {
		return 2;
	}
	memset(seed, 0x5a, sizeof(seed));
	if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
		return 3;
	}

	for (i = 0; i < 64; ++i) {
		unsigned long long got = ss_len;
		fill(pk, (size_t)pk_len);
		fill(sk, (size_t)sk_len);
		fill(ct, (size_t)ct_len);
		(void)kem_enc(pk, pk_len, ss, &got, ct, (unsigned long long[]){ct_len});
		got = ss_len;
		(void)kem_dec(sk, sk_len, ct, ct_len, ss, &got);
	}

	free(ss);
	free(ct);
	free(sk);
	free(pk);
	return 0;
}
