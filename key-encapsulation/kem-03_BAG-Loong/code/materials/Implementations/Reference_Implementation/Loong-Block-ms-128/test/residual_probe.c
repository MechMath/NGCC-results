#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "KEM_AlgorithmInstance.h"
#include "loong_pke.h"

DRNG_ctx drng_algorithm;

int main(int argc, char **argv)
{
	unsigned long long trials = 1000;
	unsigned char seed[64];
	unsigned long long pk_len = kem_get_pk_len_bytes();
	unsigned long long sk_len = kem_get_sk_len_bytes();
	unsigned long long ss_len = kem_get_ss_len_bytes();
	unsigned long long ct_len = kem_get_ct_len_bytes();
	unsigned char *pk = calloc(pk_len, 1);
	unsigned char *sk = calloc(sk_len, 1);
	unsigned char *ss = calloc(ss_len, 1);
	unsigned char *ss1 = calloc(ss_len, 1);
	unsigned char *ct = calloc(ct_len, 1);
	unsigned char *m = calloc(loong_pke_get_message_len_bytes(), 1);
	unsigned long long keygen_fail = 0, enc_fail = 0, dec_fail = 0;
	unsigned long long pke_fail = 0, kem_fail = 0, ss_mismatch = 0;
	unsigned long long max_rank = 0, hist[48] = {0};
	unsigned long long i;

	if (argc > 1) {
		trials = strtoull(argv[1], 0, 10);
	}
	if (pk == 0 || sk == 0 || ss == 0 || ss1 == 0 || ct == 0 || m == 0) {
		return 2;
	}
	for (i = 0; i < sizeof(seed); i++) {
		seed[i] = (unsigned char)(i * 37U + 11U);
	}
	init_random_number(&drng_algorithm, seed, sizeof(seed) * 8ULL);

	for (i = 0; i < trials; i++) {
		unsigned int rank = 0;
		int rc;
		pk_len = kem_get_pk_len_bytes();
		sk_len = kem_get_sk_len_bytes();
		ss_len = kem_get_ss_len_bytes();
		ct_len = kem_get_ct_len_bytes();
		rc = kem_keygen(pk, &pk_len, sk, &sk_len);
		if (rc != 0) {
			keygen_fail++;
			continue;
		}
		rc = kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);
		if (rc != 0) {
			enc_fail++;
			continue;
		}
		rc = loong_pke_decrypt_with_residual_rank(
			m, loong_pke_get_message_len_bytes(), &rank, sk, 2500, ct, 3055);
		if (rc != 0) {
			pke_fail++;
		}
		if (rank < 48) {
			hist[rank]++;
		}
		if (rank > max_rank) {
			max_rank = rank;
		}
		memset(ss1, 0, ss_len);
		rc = kem_dec(sk, sk_len, ct, ct_len, ss1, &ss_len);
		if (rc != 0) {
			kem_fail++;
		} else if (memcmp(ss, ss1, ss_len) != 0) {
			ss_mismatch++;
		} else {
			dec_fail++;
		}
	}
	printf("trials=%llu keygen_fail=%llu enc_fail=%llu pke_fail=%llu "
	       "kem_fail=%llu ss_mismatch=%llu dec_success=%llu max_rank=%llu\n",
	       trials, keygen_fail, enc_fail, pke_fail, kem_fail, ss_mismatch,
	       dec_fail, max_rank);
	for (i = 0; i < 48; i++) {
		if (hist[i] != 0) {
			printf("rank[%llu]=%llu\n", i, hist[i]);
		}
	}
	return 0;
}
