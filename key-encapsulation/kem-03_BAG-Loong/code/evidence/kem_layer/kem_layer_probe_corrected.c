#include "KEM_AlgorithmInstance.h"
#include "auxfunc.h"
#include "drng.h"

#include <stdio.h>
#include <string.h>

DRNG_ctx drng_algorithm;

static void print_hex(const char *label, const unsigned char *p, size_t n)
{
	size_t i;
	printf("%s", label);
	for (i = 0; i < n; i++) {
		printf("%02X", p[i]);
	}
	printf("\n");
}

int main(void)
{
	static const unsigned char msg[] = "BAG-Loong primitive audit input";
	unsigned char seed[64];
	unsigned char pk[19043];
	unsigned char sk[44512];
	unsigned char ct[21660];
	unsigned char ct_bad1[21660];
	unsigned char ct_bad2[21660];
	unsigned char ss[64];
	unsigned char ss_bad1[64];
	unsigned char ss_bad1_repeat[64];
	unsigned char ss_bad2[64];
	unsigned char fallback_keys[256][64];
	unsigned char salt_fallback_keys[16][64];
	unsigned char hash[64];
	unsigned char xof[64];
	unsigned long long pk_len;
	unsigned long long sk_len;
	unsigned long long ct_len;
	unsigned long long ss_len;
	int rc_keygen;
	int rc_enc;
	int rc_dec_valid;
	int rc_dec_bad1;
	int rc_dec_bad1_repeat;
	int rc_dec_bad2;
	unsigned int core_fallback_count = 0;
	unsigned int salt_fallback_count = 0;
	size_t i;
	size_t j;

	memset(seed, 0x42, sizeof(seed));
	init_random_number(&drng_algorithm, seed, sizeof(seed));

	pk_len = kem_get_pk_len_bytes();
	sk_len = kem_get_sk_len_bytes();
	ct_len = kem_get_ct_len_bytes();
	ss_len = kem_get_ss_len_bytes();
	rc_keygen = kem_keygen(pk, &pk_len, sk, &sk_len);
	rc_enc = kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len);
	rc_dec_valid = kem_dec(sk, sk_len, ct, ct_len, ss, &ss_len);

	/* Positive control: the generated ciphertext decapsulates successfully. */
	printf("primitive_input=");
	print_hex("", msg, sizeof(msg) - 1);
	if (pseudohash(512, msg, (sizeof(msg) - 1) * 8ULL, hash) != 0) {
		return 2;
	}
	print_hex("implementation_G=", hash, sizeof(hash));
	if (pseudoXOF(512, msg, (sizeof(msg) - 1) * 8ULL, xof) != 0) {
		return 3;
	}
	print_hex("implementation_K=", xof, sizeof(xof));
	printf("keygen_rc=%d encaps_rc=%d valid_decap_rc=%d\n",
	       rc_keygen, rc_enc, rc_dec_valid);

	/* A one-bit perturbation in the first ciphertext byte. */
	memcpy(ct_bad1, ct, ct_len);
	ct_bad1[0] ^= 1;
	rc_dec_bad1 = kem_dec(sk, sk_len, ct_bad1, ct_len, ss_bad1, &ss_len);
	rc_dec_bad1_repeat =
		kem_dec(sk, sk_len, ct_bad1, ct_len, ss_bad1_repeat, &ss_len);

	/* A second, distinct one-bit perturbation. */
	memcpy(ct_bad2, ct, ct_len);
	ct_bad2[0] ^= 2;
	rc_dec_bad2 = kem_dec(sk, sk_len, ct_bad2, ct_len, ss_bad2, &ss_len);

	printf("bad1_decap_rc=%d repeat_rc=%d bad2_decap_rc=%d\n",
	       rc_dec_bad1, rc_dec_bad1_repeat, rc_dec_bad2);
	print_hex("bad1_ss=", ss_bad1, 16);
	print_hex("bad1_repeat_ss=", ss_bad1_repeat, 16);
	print_hex("bad2_ss=", ss_bad2, 16);
	printf("bad1_deterministic=%d bad1_vs_bad2_distinct=%d\n",
	       memcmp(ss_bad1, ss_bad1_repeat, 16) == 0,
	       memcmp(ss_bad1, ss_bad2, 16) != 0);

	/*
	 * Exercise 256 single-bit mutations across the first 32 ciphertext-core
	 * bytes. Distinct ciphertexts are compared by complete API ciphertext
	 * bytes; session keys are compared over the implementation's 16-byte
	 * BAG-Loong-128 shared secret.
	 */
	for (i = 0; i < 256; i++) {
		unsigned int seen = 0;
		memcpy(ct_bad1, ct, ct_len);
		ct_bad1[i / 8] ^= (unsigned char)(1U << (i % 8));
		rc_dec_bad1 =
			kem_dec(sk, sk_len, ct_bad1, ct_len,
			        fallback_keys[core_fallback_count], &ss_len);
		if (rc_dec_bad1 != -1) {
			printf("unexpected_core_mutation_rc index=%zu rc=%d\n",
			       i, rc_dec_bad1);
			return 4;
		}
		for (j = 0; j < core_fallback_count; j++) {
			if (memcmp(fallback_keys[j],
			           fallback_keys[core_fallback_count], 16) == 0) {
				seen = 1;
				break;
			}
		}
		if (!seen) {
			core_fallback_count++;
		}
	}

	/* Negative control: salt mutations change the recomputed fallback input. */
	for (i = 0; i < 16; i++) {
		unsigned int seen = 0;
		memcpy(ct_bad1, ct, ct_len);
		ct_bad1[ct_len - 16 + i] ^= 1;
		rc_dec_bad1 =
			kem_dec(sk, sk_len, ct_bad1, ct_len,
			        salt_fallback_keys[salt_fallback_count], &ss_len);
		if (rc_dec_bad1 != -1) {
			printf("unexpected_salt_mutation_rc index=%zu rc=%d\n",
			       i, rc_dec_bad1);
			return 5;
		}
		for (j = 0; j < salt_fallback_count; j++) {
			if (memcmp(salt_fallback_keys[j],
			           salt_fallback_keys[salt_fallback_count], 16) == 0) {
				seen = 1;
				break;
			}
		}
		if (!seen) {
			salt_fallback_count++;
		}
	}
	printf("core_mutations=256 distinct_core_fallback_keys=%u\n",
	       core_fallback_count);
	printf("salt_mutations=16 distinct_salt_fallback_keys=%u\n",
	       salt_fallback_count);

	for (i = 0; i < 256; i++) {
		for (j = 0; j < 16; j++) {
			fallback_keys[i][j] = 0;
		}
	}
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++) {
			salt_fallback_keys[i][j] = 0;
		}
	}
	for (i = 0; i < 16; i++) {
		ss_bad1[i] = 0;
		ss_bad1_repeat[i] = 0;
		ss_bad2[i] = 0;
	}
	return 0;
}
