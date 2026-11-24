#include <stdio.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

int main(void)
{
	unsigned char seed[64], pk[2500], sk[5064], ct[3071], ss[16];
	unsigned char bad_ct[3071], rejected_ss[16];
	unsigned long long pkl = sizeof(pk), skl = sizeof(sk);
	unsigned long long ctl = sizeof(ct), ssl = sizeof(ss);

	for (unsigned int i = 0; i < sizeof(seed); i++)
		seed[i] = (unsigned char)i;
	init_random_number(&drng_algorithm, seed, sizeof(seed));
	if (kem_keygen(pk, &pkl, sk, &skl) != 0)
		return 2;
	if (kem_enc(pk, pkl, ss, &ssl, ct, &ctl) != 0)
		return 3;
	memcpy(bad_ct, ct, sizeof(bad_ct));
	bad_ct[0] ^= 1U;
	int status = kem_dec(sk, skl, bad_ct, ctl, rejected_ss, &ssl);
	printf("kem_dec_status=%d ss_len=%llu rejected_ss_nonzero=%d\n",
	       status, ssl, memcmp(rejected_ss, (unsigned char[16]){0}, 16) != 0);
	return status == 0 ? 0 : 1;
}
