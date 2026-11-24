#include "api.h"
#include "sign.h"
#include "mpc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int first_response_round(const unsigned char *sig)
{
    unsigned char chall2[PARAM_TAU];
    mpc_gen_chall2(chall2, sig + SIG_OFF_DIGEST_CHALL2);
    for (int i = 0; i < PARAM_TAU; i++) if (chall2[i] == 0) return i;
    return -1;
}

int main(void)
{
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char sig[CRYPTO_BYTES], bad[CRYPTO_BYTES];
    unsigned char extended[CRYPTO_BYTES + 1];
    unsigned char msg[] = "canonicality controls";
    size_t siglen = 0;
    if (crypto_sign_keypair(pk, sk) || crypto_sign_signature(sig, &siglen, msg, sizeof(msg)-1, sk))
        return 2;

    int target = first_response_round(sig);
    if (target < 0) return 2;

    unsigned char chall2[PARAM_TAU];
    mpc_gen_chall2(chall2, sig + SIG_OFF_DIGEST_CHALL2);
    size_t op = SIG_OFF_PATH, opr = SIG_OFF_PROOF, ore = SIG_OFF_RESP;
    for (int i = 0; i < target; i++) {
        if (chall2[i] == 1) {
            op += PARAM_SEED_BYTES;
            opr += PARAM_HASH_BYTES;
        } else {
            ore += QINGLUAN_Y_BYTES + QINGLUAN_V_BYTES + PARAM_HASH_BYTES;
        }
    }
    if (chall2[target] != 0) return 2;

    printf("response_round=%d y_off=%zu v_off=%zu\n",
           target, ore, ore + QINGLUAN_Y_BYTES);

    int honest = crypto_sign_verify(sig, siglen, msg, sizeof(msg)-1, pk);

    memcpy(bad, sig, sizeof(bad));
    bad[ore + QINGLUAN_Y_BYTES - 1] |= 0x80;
    int ypad = crypto_sign_verify(bad, siglen, msg, sizeof(msg)-1, pk);

    memcpy(bad, sig, sizeof(bad));
    bad[ore + QINGLUAN_Y_BYTES + QINGLUAN_V_BYTES - 1] |= 0x80;
    int vpad = crypto_sign_verify(bad, siglen, msg, sizeof(msg)-1, pk);

    memcpy(bad, sig, sizeof(bad));
    bad[CRYPTO_PUBLICKEYBYTES - 1] |= 0x80;
    int pkpad_verify = crypto_sign_verify(sig, siglen, msg, sizeof(msg)-1, bad);

    int truncate = crypto_sign_verify(sig, siglen - 1, msg, sizeof(msg)-1, pk);
    memcpy(extended, sig, siglen); extended[siglen] = 0;
    int extend = crypto_sign_verify(extended, siglen + 1, msg, sizeof(msg)-1, pk);

    printf("honest=%d y_pad=%d v_pad=%d pk_pad=%d truncate=%d extend=%d\n",
           honest, ypad, vpad, pkpad_verify, truncate, extend);
    return (honest == 0 && ypad != 0 && vpad != 0 && pkpad_verify != 0 &&
            truncate != 0 && extend != 0) ? 0 : 1;
}
