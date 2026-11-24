#include "KEM_AlgorithmInstance.h"
#include "drng.h"
#include "loong_parameters.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DRNG_ctx drng_algorithm;

static void print_hex(const unsigned char *p, unsigned long long n)
{
	unsigned long long i;

	for (i = 0; i < n; i++) {
		printf("%02X", p[i]);
	}
}

static int same_secret(const unsigned char *a, const unsigned char *b)
{
	return memcmp(a, b, LOONG_SS_BYTES) == 0;
}

int main(void)
{
	unsigned char seed[64];
	unsigned char *pk = NULL;
	unsigned char *sk = NULL;
	unsigned char *ct = NULL;
	unsigned char *mut = NULL;
	unsigned char ss[LOONG_SS_BYTES];
	unsigned char got[LOONG_SS_BYTES];
	unsigned char first_core[LOONG_SS_BYTES];
	unsigned char salt_secrets[LOONG_SALT_BYTES][LOONG_SS_BYTES];
	unsigned long long pk_len = kem_get_pk_len_bytes();
	unsigned long long sk_len = kem_get_sk_len_bytes();
	unsigned long long ct_len = kem_get_ct_len_bytes();
	unsigned long long ss_len = kem_get_ss_len_bytes();
	unsigned int i;
	unsigned int j;
	unsigned int distinct_core = 0;
	unsigned int distinct_salt = 0;
	int rc;

	memset(seed, 0x42, sizeof(seed));
	init_random_number(&drng_algorithm, seed, sizeof(seed));

	pk = calloc((size_t)pk_len, 1);
	sk = calloc((size_t)sk_len, 1);
	ct = calloc((size_t)ct_len, 1);
	mut = calloc((size_t)ct_len, 1);
	if (pk == NULL || sk == NULL || ct == NULL || mut == NULL) {
		return 2;
	}

	rc = kem_keygen(pk, &pk_len, sk, &sk_len);
	if (rc != 0) {
		fprintf(stderr, "kem_keygen=%d\n", rc);
		return 3;
	}
	rc = kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);
	if (rc != 0) {
		fprintf(stderr, "kem_enc=%d\n", rc);
		return 4;
	}
	rc = kem_dec(sk, sk_len, ct, ct_len, got, &ss_len);
	if (rc != 0 || !same_secret(ss, got)) {
		fprintf(stderr, "valid decapsulation failed rc=%d equal=%d\n", rc,
		        same_secret(ss, got));
		return 5;
	}

	for (i = 0; i < 256; i++) {
		memcpy(mut, ct, (size_t)ct_len);
		mut[i / 8] ^= (unsigned char)(1U << (i % 8));
		memset(got, 0, sizeof(got));
		rc = kem_dec(sk, sk_len, mut, ct_len, got, &ss_len);
		if (rc != -1) {
			fprintf(stderr, "core mutation %u returned %d\n", i, rc);
			return 6;
		}
		if (i == 0) {
			memcpy(first_core, got, sizeof(first_core));
			distinct_core = 1;
		} else if (!same_secret(first_core, got)) {
			distinct_core++;
		}
	}

	for (i = 0; i < LOONG_SALT_BYTES; i++) {
		unsigned int unique = 1;

		memcpy(mut, ct, (size_t)ct_len);
		mut[LOONG_PKE_CT_BYTES + i] ^= 1;
		memset(got, 0, sizeof(got));
		rc = kem_dec(sk, sk_len, mut, ct_len, got, &ss_len);
		if (rc != -1) {
			fprintf(stderr, "salt mutation %u returned %d\n", i, rc);
			return 7;
		}
		memcpy(salt_secrets[i], got, sizeof(got));
		for (j = 0; j < i; j++) {
			if (same_secret(salt_secrets[j], got)) {
				unique = 0;
				break;
			}
		}
		distinct_salt += unique;
	}

	printf("valid=0 valid_equal=1\n");
	printf("core_mutations=256 distinct_core_fallback_keys=%u\n", distinct_core);
	printf("core_fallback=");
	print_hex(first_core, sizeof(first_core));
	printf("\n");
	printf("salt_mutations=%u distinct_salt_fallback_keys=%u\n",
	       (unsigned int)LOONG_SALT_BYTES, distinct_salt);

	free(pk);
	free(sk);
	free(ct);
	free(mut);
	return 0;
}
