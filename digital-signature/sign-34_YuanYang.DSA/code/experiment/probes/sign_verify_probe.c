#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"

static unsigned char *
read_file(const char *path, size_t expected, size_t *actual)
{
	FILE *f;
	unsigned char *buf;
	size_t n;

	f = fopen(path, "rb");
	if (f == NULL) {
		return NULL;
	}
	buf = malloc(expected);
	if (buf == NULL) {
		fclose(f);
		return NULL;
	}
	n = fread(buf, 1, expected, f);
	if (ferror(f) || fgetc(f) != EOF) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	*actual = n;
	return buf;
}

static int
write_file(const char *path, const void *buf, size_t len)
{
	FILE *f;

	f = fopen(path, "wb");
	if (f == NULL) {
		return 0;
	}
	if (fwrite(buf, 1, len, f) != len || fclose(f) != 0) {
		return 0;
	}
	return 1;
}

int
main(int argc, char **argv)
{
	static const unsigned char message[] =
		"attacker-selected message under victim public key";
	unsigned char *pk, *sk = NULL, *sig;
	size_t pk_actual, sk_actual, sig_actual;
	unsigned long long sn_len;
	int rc;

	if (argc != 5 || (strcmp(argv[1], "sign") != 0
		&& strcmp(argv[1], "verify") != 0))
	{
		fprintf(stderr, "usage: %s sign|verify PK SK|SIG OUTPUT\n", argv[0]);
		return 2;
	}
	pk = read_file(argv[2], (size_t)sig_get_pk_len_bytes(), &pk_actual);
	if (pk == NULL || pk_actual != (size_t)sig_get_pk_len_bytes()) {
		free(pk);
		return 3;
	}
	if (strcmp(argv[1], "sign") == 0) {
		sk = read_file(argv[3], (size_t)sig_get_sk_len_bytes(), &sk_actual);
		sig = malloc((size_t)sig_get_sn_len_bytes());
		if (sk == NULL || sig == NULL
			|| sk_actual != (size_t)sig_get_sk_len_bytes())
		{
			free(pk);
			free(sk);
			free(sig);
			return 4;
		}
		sn_len = sig_get_sn_len_bytes();
		rc = sig_sign(sk, sk_actual, (unsigned char *)message,
			sizeof message - 1u, sig, &sn_len);
		printf("sign rc=%d sn_len=%llu\n", rc, sn_len);
		if (rc != 0 || !write_file(argv[4], sig, (size_t)sn_len)) {
			free(pk);
			free(sk);
			free(sig);
			return 1;
		}
	} else {
		sig = read_file(argv[3], (size_t)sig_get_sn_len_bytes(), &sig_actual);
		if (sig == NULL || sig_actual != (size_t)sig_get_sn_len_bytes()) {
			free(pk);
			free(sig);
			return 4;
		}
		rc = sig_verify(pk, pk_actual, sig, sig_actual,
			(unsigned char *)message, sizeof message - 1u);
		printf("verify rc=%d (0 means accepted)\n", rc);
		if (!write_file(argv[4], &rc, sizeof rc)) {
			free(pk);
			free(sig);
			return 1;
		}
	}
	free(pk);
	free(sk);
	free(sig);
	return rc == 0 ? 0 : 1;
}
