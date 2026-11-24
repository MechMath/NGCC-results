#include <stdio.h>
#include <string.h>

#include "auxfunc.h"

static void print_hex(const unsigned char *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		printf("%02x", p[i]);
	}
}

int main(void)
{
	static const unsigned char abc[] = {'a', 'b', 'c'};
	static const unsigned char expected[32] = {
		0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
		0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
		0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
		0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
	};
	static const unsigned char msg[] = {0x11, 0x22, 0x33};
	unsigned char digest[32];
	unsigned char xof64[64];
	unsigned char xof128[128];
	int rc;

	rc = sm3hash(256, abc, 8u * sizeof abc, digest);
	printf("sm3_abc_rc=%d\nsm3_abc=", rc);
	print_hex(digest, sizeof digest);
	printf("\nsm3_abc_matches_gb32905=%d\n",
		memcmp(digest, expected, sizeof digest) == 0);

	rc = pseudoXOF(512, msg, 8u * sizeof msg, xof64);
	printf("xof64_rc=%d\nxof64=", rc);
	print_hex(xof64, sizeof xof64);
	printf("\n");

	rc = pseudoXOF(1024, msg, 8u * sizeof msg, xof128);
	printf("xof128_rc=%d\nxof128_prefix_matches=%d\nxof128=", rc,
		memcmp(xof64, xof128, sizeof xof64) == 0);
	print_hex(xof128, sizeof xof128);
	printf("\n");
	return 0;
}
