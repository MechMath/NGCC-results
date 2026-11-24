#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "params.h"
#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

int sig_keygen(unsigned char *, unsigned long long *, unsigned char *,
               unsigned long long *);
int sig_sign(const unsigned char *, unsigned long long, const unsigned char *,
             unsigned long long, unsigned char *, unsigned long long *);
int sig_verify(const unsigned char *, unsigned long long, const unsigned char *,
               unsigned long long, unsigned char *, unsigned long long);

int main(void)
{
  static unsigned char seed[64] = {
    0x92,0x7F,0x06,0xB5,0x94,0x79,0x8A,0x4D,0xDF,0xAA,0x4F,0x03,0xF9,0x2A,0xAA,0xF0,
    0x4E,0x1D,0x45,0x3F,0x6E,0xD1,0xDE,0x19,0xB8,0x6D,0x3A,0xAD,0xE0,0x48,0xA6,0x54,
    0x83,0xDF,0x47,0x54,0x04,0x9B,0x5C,0xD3,0xF5,0x86,0x40,0x6C,0xF2,0xC6,0x48,0x75,
    0xC5,0x1E,0xDB,0x57,0x6D,0xF3,0x42,0xB5,0xA9,0x70,0xF4,0x0E,0xAB,0xC1,0x5D,0x3C
  };
  static unsigned char message[56] = {
    0xEE,0x40,0x2D,0x17,0x30,0xD0,0x11,0x7B,0x9F,0x51,0xBE,0x06,0x72,0x59,0x2F,0xCE,
    0xC4,0x38,0xA2,0x94,0x5A,0x81,0xF5,0xD8,0x94,0xB8,0x69,0xDC,0x86,0x3C,0xCB,0xF5,
    0x7E,0x5C,0x8E,0x77,0x66,0xD7,0x4E,0x27,0xE9,0x65,0x23,0x5C,0xD9,0x1E,0x5E,0x30,
    0xE5,0x58,0x31,0x67,0x05,0x3E,0x10,0x14
  };
  unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  unsigned char sn[CRYPTO_BYTES + sizeof(message)], recovered[sizeof(message)];
  unsigned long long pklen = 0, sklen = 0, snlen = 0;
  size_t hint_end, i;
  int before, after;
  FILE *f;

  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) return 2;
  if (sig_keygen(pk, &pklen, sk, &sklen) != 0) return 3;
  if (sig_sign(sk, sklen, message, sizeof(message), sn, &snlen) != 0) return 4;

  memcpy(recovered, message, sizeof(message));
  before = sig_verify(pk, pklen, sn, snlen, recovered, sizeof(message));
  hint_end = L * (N * (QBITS - 3) / 8) + sn[L * (N * (QBITS - 3) / 8) + OMEGA + K - 1];
  printf("pk=%llu sk=%llu sn=%llu before=%d message_match=%d hint_end=%zu\n",
         pklen, sklen, snlen, before,
         before == 0 && !memcmp(message, recovered, sizeof(message)), hint_end);
  if (hint_end >= L * (N * (QBITS - 3) / 8) + OMEGA) return 5;
  printf("hint_padding_byte_index=%zu original=%u\n", hint_end, sn[hint_end]);
  f = fopen("original_signature.bin", "wb");
  if (!f) return 6;
  fwrite(sn, 1, CRYPTO_BYTES, f);
  fclose(f);
  sn[hint_end] ^= 1;
  f = fopen("mutated_signature.bin", "wb");
  if (!f) return 6;
  fwrite(sn, 1, CRYPTO_BYTES, f);
  fclose(f);
  memcpy(recovered, message, sizeof(message));
  after = sig_verify(pk, pklen, sn, snlen, recovered, sizeof(message));
  printf("after=%d message_match=%d mutated_value=%u\n", after,
         after == 0 && !memcmp(message, recovered, sizeof(message)), sn[hint_end]);

  f = fopen("malleability_result.bin", "wb");
  if (!f) return 6;
  fwrite(pk, 1, pklen, f); fwrite(sn, 1, snlen, f);
  fclose(f);
  return before == 0 && after == 0 ? 0 : 7;
}
