#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "SIG_AlgorithmInstance.h"

extern DRNG_ctx drng_algorithm;

int
main(int argc, char **argv)
{
	FILE *f;
	unsigned char *pk;
	unsigned long long pk_len;
	unsigned char *sk;
	unsigned long long sk_len;
	int rc;

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "usage: %s PK_OUTPUT SK_OUTPUT [SEED]\n", argv[0]);
		return 2;
	}
	if (argc == 4
		&& init_random_number(&drng_algorithm,
			(const unsigned char *)argv[3], strlen(argv[3])) != 0)
	{
		return 6;
	}
	pk = malloc((size_t)sig_get_pk_len_bytes());
	sk = malloc((size_t)sig_get_sk_len_bytes());
	if (pk == NULL || sk == NULL) {
		free(pk);
		free(sk);
		return 3;
	}
	pk_len = sig_get_pk_len_bytes();
	sk_len = sig_get_sk_len_bytes();
	rc = sig_keygen(pk, &pk_len, sk, &sk_len);
	printf("rc=%d pk_len=%llu sk_len=%llu\n",
		rc, pk_len, sk_len);
	if (rc != 0) {
		free(pk);
		free(sk);
		return 1;
	}
	f = fopen(argv[1], "wb");
	if (f == NULL
		|| fwrite(pk, 1, (size_t)pk_len, f) != (size_t)pk_len
		|| fclose(f) != 0)
	{
		free(pk);
		free(sk);
		return 4;
	}
	f = fopen(argv[2], "wb");
	if (f == NULL
		|| fwrite(sk, 1, (size_t)sk_len, f) != (size_t)sk_len
		|| fclose(f) != 0)
	{
		free(pk);
		free(sk);
		return 5;
	}
	free(pk);
	free(sk);
	return 0;
}
