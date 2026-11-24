#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "params.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"

static int read_signature(const char *path, uint8_t sig[CRYPTO_SIGNATUREBYTES])
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 1;
    }
    size_t got = fread(sig, 1, CRYPTO_SIGNATUREBYTES, f);
    fclose(f);
    return got != CRYPTO_SIGNATUREBYTES;
}

int main(int argc, char **argv)
{
    uint8_t raw1[CRYPTO_SIGNATUREBYTES];
    uint8_t raw2[CRYPTO_SIGNATUREBYTES];
    poly c1, c2;
    polyvecl low1, low2, high1, high2;
    polyveck h1, h2;

    if (argc != 3 ||
        read_signature(argv[1], raw1) != 0 ||
        read_signature(argv[2], raw2) != 0) {
        return 2;
    }
    if (unpack_sig(&c1, &low1, &high1, &h1, raw1) != 0 ||
        unpack_sig(&c2, &low2, &high2, &h2, raw2) != 0) {
        return 3;
    }

    int same_c = memcmp(c1.coeffs, c2.coeffs, sizeof(c1.coeffs)) == 0;
    int same_low = memcmp(&low1, &low2, sizeof(low1)) == 0;
    int same_high = memcmp(&high1, &high2, sizeof(high1)) == 0;
    int same_h = memcmp(&h1, &h2, sizeof(h1)) == 0;
    int raw_equal = memcmp(raw1, raw2, sizeof(raw1)) == 0;

    printf("raw_equal=%d c_equal=%d low_equal=%d high_equal=%d h_equal=%d\n",
           raw_equal, same_c, same_low, same_high, same_h);
    return (same_c && same_low && same_high && same_h && !raw_equal) ? 0 : 4;
}
