#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

int main(void)
{
    static const unsigned char message[] =
        "OPS-SIG hint-padding malleability test";
    uint8_t seed[55];
    unsigned char pk[6720];
    unsigned char sk[9920];
    unsigned char sig[12021];
    unsigned long long pk_len = sig_get_pk_len_bytes();
    unsigned long long sk_len = sig_get_sk_len_bytes();
    unsigned long long sig_len = 0;
    int keygen_rc;
    int original_rc;
    int mutated_rc;
    unsigned int padding_byte;
    unsigned char padding_mask;

    /*
     * The encoded hint starts after ctilde and L packed z polynomials.
     * For OMEGA=85, 765 bits are used in a 96-byte field, leaving the top
     * three bits of hint byte 95 unused.  For OMEGA=90 with ten-bit
     * positions, 900 bits are used in a 113-byte field, leaving the top
     * four bits of hint byte 112 unused.
     */
#if OMEGA == 85
    padding_byte = CTILDEBYTES + L * POLYZ_PACKEDBYTES + 95;
    padding_mask = 0x80;
#elif OMEGA == 90
    padding_byte = CTILDEBYTES + L * POLYZ_PACKEDBYTES + 112;
    padding_mask = 0x10;
#else
#error "This test targets the non-byte-aligned AVX2 hint encodings"
#endif

    for (unsigned int i = 0; i < sizeof(seed); ++i)
        seed[i] = (uint8_t)(0xA7 ^ (uint8_t)(3 * i));

    if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0)
        return 2;

    keygen_rc = sig_keygen(pk, &pk_len, sk, &sk_len);
    original_rc = sig_sign(sk, sk_len, (unsigned char *)message,
                           sizeof(message) - 1, sig, &sig_len);
    if (keygen_rc != 0 || original_rc != 0 || sig_len != sig_get_sn_len_bytes())
        return 3;

    original_rc = sig_verify(pk, pk_len, sig, sig_len,
                             (unsigned char *)message, sizeof(message) - 1);
    if (original_rc != 0)
        return 4;

    if ((sig[padding_byte] & padding_mask) != 0)
        return 5;
    sig[padding_byte] ^= padding_mask;

    mutated_rc = sig_verify(pk, pk_len, sig, sig_len,
                            (unsigned char *)message, sizeof(message) - 1);

    printf("implementation=%s profile=%s\n",
           IMPLEMENTATION_VARIANT, ALGORITHM_INSTANCE);
    printf("signature_bytes=%llu padding_byte=%u padding_mask=0x%02x\n",
           sig_len, padding_byte, padding_mask);
    printf("original_verify_rc=%d mutated_verify_rc=%d\n",
           original_rc, mutated_rc);
    return 0;
}
