#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "yuanyang_params.h"

DRNG_ctx drng_algorithm;

static uint64_t read_lsb_bits(const unsigned char *p, size_t bitoff, unsigned n)
{
	uint64_t v = 0;
	for (unsigned i = 0; i < n; i++) {
		size_t bit = bitoff + i;
		v |= (uint64_t)((p[bit >> 3] >> (bit & 7u)) & 1u) << i;
	}
	return v;
}

static void write_lsb_bits(unsigned char *p, size_t bitoff, unsigned n, uint64_t v)
{
	for (unsigned i = 0; i < n; i++) {
		size_t bit = bitoff + i;
		unsigned char mask = (unsigned char)(1u << (bit & 7u));
		if ((v >> i) & 1u) {
			p[bit >> 3] |= mask;
		} else {
			p[bit >> 3] &= (unsigned char)~mask;
		}
	}
}

static int expect_status(const char *name, int rc, int valid)
{
	int ok = valid ? (rc == 0) : (rc != 0);
	printf("case=%s rc=%d expected=%s result=%s\n",
		name, rc, valid ? "valid" : "invalid", ok ? "PASS" : "FAIL");
	return ok;
}

static int make_public_key_alias(unsigned char *alias, const unsigned char *pk)
{
	/* Adding q^k to one packed block leaves all base-q coefficients
	 * unchanged and is representable when the block has a spare high code. */
	uint64_t qk = 1;
	const uint64_t cap = UINT64_C(1) << YUANYANG_PK_BLOCK_BITS;
	const unsigned blocks = YUANYANG_D / YUANYANG_PK_BLOCK_COEFFS;
	for (unsigned i = 0; i < YUANYANG_PK_BLOCK_COEFFS; i++)
		qk *= YUANYANG_Q;

	memcpy(alias, pk, sig_get_pk_len_bytes());
	for (unsigned i = 0; i < blocks; i++) {
		size_t off = 8u * YUANYANG_PK_PREFIX_BYTES
			+ YUANYANG_PK_BLOCK_BITS * i;
		uint64_t word = read_lsb_bits(
			alias, off, YUANYANG_PK_BLOCK_BITS);
		if (word < cap - qk) {
			write_lsb_bits(alias, off, YUANYANG_PK_BLOCK_BITS,
				word + qk);
			printf("alias_block=%u original_word=%llu alias_word=%llu "
				"q_power=%llu block_bits=%u\n",
				i, (unsigned long long)word,
				(unsigned long long)(word + qk),
				(unsigned long long)qk,
				(unsigned)YUANYANG_PK_BLOCK_BITS);
			return 1;
		}
	}
	return 0;
}

int main(void)
{
	const unsigned char msg[] = "YuanYang verifier surface positive control";
	const unsigned char wrong[] = "YuanYang verifier surface wrong message";
	unsigned char nonce[64];
	unsigned char *pk = NULL, *sk = NULL, *sn = NULL, *tmp = NULL;
	unsigned long long pkcap, skcap, sncap, pklen, sklen, snlen;
	int ok = 1, accepted_pk_flips = 0, accepted_sn_flips = 0;
	int accepted_salt_flips = 0;
	char name[96];

	setvbuf(stdout, NULL, _IONBF, 0);
	for (unsigned i = 0; i < sizeof nonce; i++)
		nonce[i] = (unsigned char)(0xA5u ^ i);
	if (init_random_number(&drng_algorithm, nonce, sizeof nonce) != 0) return 2;

	pkcap = sig_get_pk_len_bytes();
	skcap = sig_get_sk_len_bytes();
	sncap = sig_get_sn_len_bytes();
	pk = malloc((size_t)pkcap);
	sk = malloc((size_t)skcap);
	sn = malloc((size_t)sncap);
	tmp = malloc((size_t)((pkcap > sncap ? pkcap : sncap) + 1u));
	if (!pk || !sk || !sn || !tmp) return 2;
	pklen = pkcap;
	sklen = skcap;
	snlen = sncap;

	ok &= expect_status("keygen", sig_keygen(pk, &pklen, sk, &sklen), 1);
	ok &= expect_status("sign", sig_sign(sk, sklen, (unsigned char *)msg,
		sizeof msg - 1u, sn, &snlen), 1);
	ok &= expect_status("valid", sig_verify(pk, pklen, sn, snlen,
		(unsigned char *)msg, sizeof msg - 1u), 1);
	ok &= expect_status("wrong_message", sig_verify(pk, pklen, sn, snlen,
		(unsigned char *)wrong, sizeof wrong - 1u), 0);

	memcpy(tmp, sn, (size_t)snlen);
	tmp[0] ^= 1u;
	ok &= expect_status("altered_salt_bit", sig_verify(pk, pklen, tmp, snlen,
		(unsigned char *)msg, sizeof msg - 1u), 0);
	memcpy(tmp, sn, (size_t)snlen);
	tmp[snlen / 2u] ^= 1u;
	ok &= expect_status("altered_payload_bit", sig_verify(pk, pklen, tmp, snlen,
		(unsigned char *)msg, sizeof msg - 1u), 0);
	ok &= expect_status("truncated_signature", sig_verify(pk, pklen, sn,
		snlen - 1u, (unsigned char *)msg, sizeof msg - 1u), 0);
	memcpy(tmp, sn, (size_t)snlen);
	tmp[snlen] = 0;
	ok &= expect_status("oversized_signature", sig_verify(pk, pklen, tmp,
		snlen + 1u, (unsigned char *)msg, sizeof msg - 1u), 0);
	memset(tmp, 0, (size_t)snlen);
	ok &= expect_status("zero_signature", sig_verify(pk, pklen, tmp, snlen,
		(unsigned char *)msg, sizeof msg - 1u), 0);

	memcpy(tmp, pk, (size_t)pklen);
	tmp[0] ^= 1u;
	ok &= expect_status("altered_q_prefix", sig_verify(tmp, pklen, sn, snlen,
		(unsigned char *)msg, sizeof msg - 1u), 0);
	ok &= expect_status("truncated_public_key", sig_verify(pk, pklen - 1u, sn,
		snlen, (unsigned char *)msg, sizeof msg - 1u), 0);

	if (make_public_key_alias(tmp, pk)) {
		ok &= expect_status("noncanonical_public_key_alias",
			sig_verify(tmp, pklen, sn, snlen, (unsigned char *)msg,
				sizeof msg - 1u), 0);
	} else {
		printf("case=noncanonical_public_key_alias construction=unavailable\n");
	}

	for (unsigned long long i = 0; i < pklen; i++) {
		for (unsigned b = 0; b < 8; b++) {
			memcpy(tmp, pk, (size_t)pklen);
			tmp[i] ^= (unsigned char)(1u << b);
			if (sig_verify(tmp, pklen, sn, snlen,
				(unsigned char *)msg, sizeof msg - 1u) == 0)
				accepted_pk_flips++;
		}
	}
	for (unsigned long long i = 0; i < YUANYANG_SALT_BYTES; i++) {
		for (unsigned b = 0; b < 8; b++) {
			memcpy(tmp, sn, (size_t)snlen);
			tmp[i] ^= (unsigned char)(1u << b);
			if (sig_verify(pk, pklen, tmp, snlen,
				(unsigned char *)msg, sizeof msg - 1u) == 0)
				accepted_salt_flips++;
		}
	}
	for (unsigned long long i = YUANYANG_SALT_BYTES; i < snlen; i++) {
		for (unsigned b = 0; b < 8; b++) {
			memcpy(tmp, sn, (size_t)snlen);
			tmp[i] ^= (unsigned char)(1u << b);
			if (sig_verify(pk, pklen, tmp, snlen,
				(unsigned char *)msg, sizeof msg - 1u) == 0)
				accepted_sn_flips++;
		}
	}
	snprintf(name, sizeof name, "single_bit_scan pk=%d sn_payload=%d salt=%d",
		accepted_pk_flips, accepted_sn_flips, accepted_salt_flips);
	printf("scan=%s\n", name);
	printf("public_key_bytes=%llu signature_bytes=%llu\n", pklen, snlen);

	printf("summary=%s\n", ok ? "PASS" : "FAIL");
	free(tmp);
	free(sn);
	free(sk);
	free(pk);
	return ok ? 0 : 1;
}
