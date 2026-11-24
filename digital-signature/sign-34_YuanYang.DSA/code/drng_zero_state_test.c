#include <stdio.h>
#include <string.h>

#include "drng.h"

int main(void)
{
	DRNG_ctx a;
	DRNG_ctx b;
	unsigned char oa[32];
	unsigned char ob[32];
	int ra;
	int rb;

	memset(&a, 0, sizeof a);
	memset(&b, 0, sizeof b);
	ra = get_random_number(&a, oa, 8u * sizeof oa);
	rb = get_random_number(&b, ob, 8u * sizeof ob);
	printf("rc_a=%d rc_b=%d equal=%d\n", ra, rb,
		memcmp(oa, ob, sizeof oa) == 0);
	for (size_t i = 0; i < sizeof oa; i++) {
		printf("%02x", oa[i]);
	}
	printf("\n");
	return 0;
}
