#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "drng.h"
#include "faest.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

static int rand_mode;
static int sign_result;
static int verify_result;
static unsigned char sign_marker = 0x5a;

int rand_bytes(uint8_t *dst, size_t len)
{
    if (rand_mode >= 0) {
        memset(dst, rand_mode, len);
    }
    return rand_mode < 0 ? -1 : 0;
}

bool faest_pubkey(uint8_t *pk, const uint8_t *sk)
{
    (void)pk;
    (void)sk;
    return true;
}

bool faest_sign(uint8_t *signature, const uint8_t *msg, size_t msg_len,
                const uint8_t *sk_packed, const uint8_t *random_seed,
                size_t random_seed_len)
{
    (void)msg;
    (void)msg_len;
    (void)sk_packed;
    (void)random_seed;
    (void)random_seed_len;
    printf("STUB faest_sign returned=%d\n", sign_result);
    if (sign_result) {
        memset(signature, sign_marker, FAEST_SIGNATURE_BYTES);
    }
    return sign_result != 0;
}

bool faest_verify(const uint8_t *signature, const uint8_t *msg, size_t msg_len,
                  const uint8_t *pk_packed)
{
    const uintptr_t sig_addr = (uintptr_t)signature;
    const uintptr_t msg_addr = (uintptr_t)msg;
    printf("STUB faest_verify signature_msg_offset=%lld msg_len=%zu return=%d\n",
           (long long)(sig_addr - msg_addr), msg_len, verify_result);
    (void)pk_packed;
    return verify_result != 0;
}

int main(void)
{
    static const unsigned char message[] = "controlled message";
    unsigned char signed_msg[sizeof(message) - 1 + FAEST_SIGNATURE_BYTES];
    unsigned char opened[sizeof(message) - 1];
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char wrapper_sn[CRYPTO_BYTES];
    unsigned long long wrapper_snlen = 0;
    unsigned long long smlen = 0;
    unsigned long long mlen = 0;

    printf("FAEST_SIGNATURE_BYTES=%d CRYPTO_BYTES=%d\n",
           FAEST_SIGNATURE_BYTES, CRYPTO_BYTES);

    memset(wrapper_sn, 0xa5, sizeof(wrapper_sn));
    rand_mode = -1;
    sign_result = 0;
    int wrapper_ret = sig_sign(sk, CRYPTO_SECRETKEYBYTES,
                               (unsigned char *)message, sizeof(message) - 1,
                               wrapper_sn, &wrapper_snlen);
    printf("WRAPPER sig_sign rand_bytes=-1 faest_sign=false ret=%d snlen=%llu "
           "signature_first_byte=0x%02x\n",
           wrapper_ret, wrapper_snlen, wrapper_sn[0]);

    memset(wrapper_sn, 0xa5, sizeof(wrapper_sn));
    sign_result = 1;
    wrapper_ret = sig_sign(sk, CRYPTO_SECRETKEYBYTES,
                           (unsigned char *)message, sizeof(message) - 1,
                           wrapper_sn, &wrapper_snlen);
    printf("WRAPPER sig_sign rand_bytes=0 faest_sign=true ret=%d snlen=%llu "
           "signature_first_byte=0x%02x\n",
           wrapper_ret, wrapper_snlen, wrapper_sn[0]);

    memset(signed_msg, 0xa5, sizeof(signed_msg));
    rand_mode = -1;
    sign_result = 0;
    int ret = crypto_sign(signed_msg, &smlen, message, sizeof(message) - 1, sk);
    printf("SIGN rand_bytes=-1 faest_sign=false crypto_sign_ret=%d smlen=%llu "
           "signature_first_byte=0x%02x\n",
           ret, smlen, signed_msg[sizeof(message) - 1]);

    memset(signed_msg, 0xa5, sizeof(signed_msg));
    rand_mode = 0;
    sign_result = 0;
    ret = crypto_sign(signed_msg, &smlen, message, sizeof(message) - 1, sk);
    printf("SIGN rand_bytes=0 faest_sign=false crypto_sign_ret=%d smlen=%llu "
           "signature_first_byte=0x%02x\n",
           ret, smlen, signed_msg[sizeof(message) - 1]);

    memset(signed_msg, 0xa5, sizeof(signed_msg));
    sign_result = 1;
    ret = crypto_sign(signed_msg, &smlen, message, sizeof(message) - 1, sk);
    printf("SIGN rand_bytes=0 faest_sign=true crypto_sign_ret=%d smlen=%llu "
           "signature_first_byte=0x%02x\n",
           ret, smlen, signed_msg[sizeof(message) - 1]);

    verify_result = 0;
    ret = crypto_sign_open(opened, &mlen, signed_msg, smlen, pk);
    printf("OPEN valid_len faest_verify=false crypto_sign_open_ret=%d mlen=%llu\n",
           ret, mlen);

    verify_result = 1;
    ret = crypto_sign_open(opened, &mlen, signed_msg, smlen, pk);
    printf("OPEN valid_len faest_verify=true crypto_sign_open_ret=%d mlen=%llu\n",
           ret, mlen);

    verify_result = 0;
    static const unsigned long long short_lengths[] = {
        0, 1, (unsigned long long)FAEST_SIGNATURE_BYTES - 1
    };
    for (size_t i = 0; i < sizeof(short_lengths) / sizeof(short_lengths[0]); ++i) {
        mlen = 0xdeadbeef;
        ret = crypto_sign_open(opened, &mlen, signed_msg,
                               short_lengths[i], pk);
        printf("OPEN short_smlen=%llu crypto_sign_open_ret=%d mlen=%llu\n",
               short_lengths[i], ret, mlen);
    }

    return 0;
}
