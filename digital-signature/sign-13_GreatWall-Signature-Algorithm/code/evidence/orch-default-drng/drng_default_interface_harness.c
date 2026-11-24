#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "api.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static void print_hex(const char *label, const unsigned char *buf, size_t len)
{
	size_t i;

	printf("%s=", label);
	for (i = 0; i < len; ++i)
		printf("%02x", buf[i]);
	putchar('\n');
}

int main(int argc, char **argv)
{
	const unsigned char message[] = "default-drng-interface-test";
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char sn[CRYPTO_BYTES];
	unsigned char seed[64];
	unsigned long long pk_len = 0;
	unsigned long long sk_len = 0;
	unsigned long long sn_len = 0;
	int ret;

	if (argc > 2)
		return 64;

	memset(pk, 0, sizeof(pk));
	memset(sk, 0, sizeof(sk));
	memset(sn, 0, sizeof(sn));
	if (argc == 2) {
		memset(seed, 0, sizeof(seed));
		memcpy(seed, argv[1], strlen(argv[1]) < sizeof(seed)
		       ? strlen(argv[1]) : sizeof(seed));
		ret = init_random_number(&drng_algorithm, seed, sizeof(seed));
		printf("init_ret=%d seed_label=%s\n", ret, argv[1]);
		if (ret != 0)
			return 4;
	}

	ret = sig_keygen(pk, &pk_len, sk, &sk_len);
	printf("keygen_ret=%d pk_len=%llu sk_len=%llu\n",
	       ret, pk_len, sk_len);
	if (ret != 0)
		return 1;

	ret = sig_sign(sk, sk_len, (unsigned char *)message,
	               sizeof(message) - 1, sn, &sn_len);
	printf("sign_ret=%d sn_len=%llu\n", ret, sn_len);
	if (ret != 0)
		return 2;

	ret = sig_verify(pk, pk_len, sn, sn_len,
	                 (unsigned char *)message, sizeof(message) - 1);
	printf("verify_ret=%d\n", ret);

	print_hex("pk", pk, sizeof(pk));
	print_hex("sk", sk, sizeof(sk));
	print_hex("sn", sn, sizeof(sn));
	return ret == 0 ? 0 : 3;
}
