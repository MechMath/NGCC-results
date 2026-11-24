#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"

/* The shipped library declares this symbol, but neither defines nor initializes it. */
DRNG_ctx drng_algorithm;

static int fresh_key_and_ct(unsigned char *pk, unsigned char *sk,
                            unsigned char *ct, unsigned char *ss)
{
	unsigned long long pk_len = kem_get_pk_len_bytes();
	unsigned long long sk_len = kem_get_sk_len_bytes();
	unsigned long long ct_len = kem_get_ct_len_bytes();
	unsigned long long ss_len = kem_get_ss_len_bytes();
	int rc;

	rc = kem_keygen(pk, &pk_len, sk, &sk_len);
	if (rc != 0) {
		return rc;
	}
	return kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);
}

int main(int argc, char **argv)
{
	const size_t pk_len = kem_get_pk_len_bytes();
	const size_t sk_len = kem_get_sk_len_bytes();
	const size_t ct_len = kem_get_ct_len_bytes();
	const size_t ss_len = kem_get_ss_len_bytes();
	unsigned char *pk1 = calloc(1, pk_len);
	unsigned char *pk2 = calloc(1, pk_len);
	unsigned char *sk1 = calloc(1, sk_len);
	unsigned char *sk2 = calloc(1, sk_len);
	unsigned char *ct1 = calloc(1, ct_len);
	unsigned char *ct2 = calloc(1, ct_len);
	unsigned char *ss1 = calloc(1, ss_len);
	unsigned char *ss2 = calloc(1, ss_len);
	unsigned char *attacker_ss = calloc(1, ss_len);
	int rc1;
	int rc2;
	int attack_rc;
	unsigned long long attacker_ss_len = ss_len;

	if (!pk1 || !pk2 || !sk1 || !sk2 || !ct1 || !ct2 || !ss1 || !ss2 ||
	    !attacker_ss) {
		return 2;
	}
	if (argc > 1) {
		unsigned char seed[64];
		memset(seed, (unsigned char)argv[1][0], sizeof(seed));
		if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
			return 5;
		}
	}
	rc1 = fresh_key_and_ct(pk1, sk1, ct1, ss1);
	rc2 = fresh_key_and_ct(pk2, sk2, ct2, ss2);
	attack_rc = kem_dec(sk1, sk_len, ct1, ct_len, attacker_ss,
	                    &attacker_ss_len);
	{
		FILE *f = fopen("rng_default_output.bin", "wb");
		if (!f) {
			return 4;
		}
		fwrite(pk1, 1, pk_len, f);
		fwrite(sk1, 1, sk_len, f);
		fwrite(ct1, 1, ct_len, f);
		fwrite(ss1, 1, ss_len, f);
		fclose(f);
	}
	printf("rc1=%d rc2=%d pk_equal=%d sk_equal=%d ct_equal=%d ss_equal=%d "
	       "attack_rc=%d recovered_ss=%d\n",
	       rc1, rc2,
	       memcmp(pk1, pk2, pk_len) == 0,
	       memcmp(sk1, sk2, sk_len) == 0,
	       memcmp(ct1, ct2, ct_len) == 0,
	       memcmp(ss1, ss2, ss_len) == 0,
	       attack_rc, memcmp(ss1, attacker_ss, ss_len) == 0);
	return (rc1 == 0 && rc2 == 0) ? 0 : 3;
}
