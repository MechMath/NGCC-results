#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"

#ifndef PROBE_PK_LEN
#define PROBE_PK_LEN 522
#endif
#ifndef PROBE_SK_LEN
#define PROBE_SK_LEN 16
#endif
#ifndef PROBE_SS_LEN
#define PROBE_SS_LEN 16
#endif

int main(void) {
  uint8_t pk[PROBE_PK_LEN];
  uint8_t sk[PROBE_SK_LEN];
  uint8_t ss[PROBE_SS_LEN];
  uint8_t short_ct[1] = {0};
  unsigned long long pk_len = sizeof(pk);
  unsigned long long sk_len = sizeof(sk);
  unsigned long long ss_len = sizeof(ss);
  unsigned long long ct_len = sizeof(short_ct);

  if (kem_keygen(pk, &pk_len, sk, &sk_len) != 0) {
    return 2;
  }
  fprintf(stderr, "calling kem_dec with declared ciphertext length %llu\n",
          ct_len);
  return kem_dec(sk, sk_len, short_ct, ct_len, ss, &ss_len);
}
