#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "SIG_AlgorithmInstance.h"

int main(void) {
    const unsigned long long pkcap = sig_get_pk_len_bytes();
    const unsigned long long skcap = sig_get_sk_len_bytes();
    const unsigned long long sncap = sig_get_sn_len_bytes();
    unsigned char *victim_pk = malloc(pkcap), *victim_sk = malloc(skcap);
    unsigned char *attacker_pk = malloc(pkcap), *attacker_sk = malloc(skcap);
    unsigned char *sig = malloc(sncap);
    unsigned char msg[] = "fresh attacker-chosen message";
    unsigned long long victim_pkn = pkcap, victim_skn = skcap;
    unsigned long long attacker_pkn = pkcap, attacker_skn = skcap, sign = sncap;
    if (!victim_pk || !victim_sk || !attacker_pk || !attacker_sk || !sig) return 2;

    /* Victim's normal NGCC key generation. */
    galas_set_kat_seed(NULL, 0);
    if (sig_keygen(victim_pk, &victim_pkn, victim_sk, &victim_skn) != 0) return 3;
    memset(victim_sk, 0, victim_skn);
    free(victim_sk);

    /* Attacker has only the public implementation source and victim_pk. */
    if (sig_keygen(attacker_pk, &attacker_pkn, attacker_sk, &attacker_skn) != 0) return 4;
    if (victim_pkn != attacker_pkn ||
        memcmp(victim_pk, attacker_pk, victim_pkn) != 0) return 5;
    if (sig_sign(attacker_sk, attacker_skn, msg, sizeof(msg) - 1, sig, &sign) != 0)
        return 6;
    int verdict = sig_verify(victim_pk, victim_pkn, sig, sign, msg, sizeof(msg) - 1);
    printf("regenerated_victim_pk=1 forged_fresh_message_verify_rc=%d\n", verdict);

    free(victim_pk); free(attacker_pk); free(attacker_sk); free(sig);
    return verdict == 0 ? 0 : 7;
}
