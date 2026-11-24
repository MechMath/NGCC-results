#include <stdio.h>
#include <stdlib.h>

#include "SIG_AlgorithmInstance.h"

static unsigned char *
read_file(const char *path, size_t cap, size_t *actual)
{
	FILE *f;
	unsigned char *buf;

	f = fopen(path, "rb");
	if (f == NULL) {
		return NULL;
	}
	buf = malloc(cap);
	if (buf == NULL) {
		fclose(f);
		return NULL;
	}
	*actual = fread(buf, 1, cap, f);
	if (ferror(f) || fgetc(f) != EOF || *actual == cap) {
		free(buf);
		fclose(f);
		return NULL;
	}
	fclose(f);
	return buf;
}

int
main(int argc, char **argv)
{
	static const unsigned char message[] =
		"attacker-selected message under victim public key";
	unsigned char *pk, *sig;
	size_t pk_len, sig_len;
	int rc;

	if (argc != 3) {
		return 2;
	}
	pk = read_file(argv[1], 10000, &pk_len);
	sig = read_file(argv[2], 10000, &sig_len);
	if (pk == NULL || sig == NULL) {
		free(pk);
		free(sig);
		return 3;
	}
	rc = sig_verify(pk, pk_len, sig, sig_len,
		(unsigned char *)message, sizeof message - 1u);
	printf("pk_len=%zu sig_len=%zu verify_rc=%d\n", pk_len, sig_len, rc);
	free(pk);
	free(sig);
	return rc == 0 ? 0 : 1;
}
