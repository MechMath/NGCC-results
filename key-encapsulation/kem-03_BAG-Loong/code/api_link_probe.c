#include <stdlib.h>

#include "KEM_AlgorithmInstance.h"

int main(void)
{
	unsigned long long pk_len = kem_get_pk_len_bytes();
	unsigned long long sk_len = kem_get_sk_len_bytes();
	unsigned char *pk = calloc(1, (size_t)pk_len);
	unsigned char *sk = calloc(1, (size_t)sk_len);
	int rc;

	if (pk == 0 || sk == 0) {
		free(pk);
		free(sk);
		return 2;
	}
	rc = kem_keygen(pk, &pk_len, sk, &sk_len);
	free(pk);
	free(sk);
	return rc == 0 ? 0 : 1;
}
