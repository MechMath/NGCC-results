#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "owcpa.h"
#include "hashkdf.h"
#include "verify.h"

#ifndef TRIALS
#define TRIALS 10000
#endif

static void decap_parts(const uint8_t *sk, const uint8_t *ct,
                        uint8_t msg[SEED_BYTES], uint8_t kr[SEED_BYTES],
                        uint8_t reenc[CT_BYTES])
{
  uint8_t buf[3 * SEED_BYTES];
  const uint8_t *pk = sk + POLYVEC_BYTES;

  owcpa_dec(buf, ct, sk);
  memcpy(msg, buf, SEED_BYTES);
  memcpy(buf + SEED_BYTES, sk + SK_BYTES - 2 * SEED_BYTES, SEED_BYTES);
  Hash2(kr, buf, 2 * SEED_BYTES);
  owcpa_enc(reenc, buf, pk, kr + SEED_BYTES);
}

static unsigned bit_distance(const uint8_t *a, const uint8_t *b, size_t len)
{
  unsigned total = 0;
  size_t i;
  for (i = 0; i < len; i++) {
    uint8_t x = a[i] ^ b[i];
    while (x) {
      total += x & 1u;
      x >>= 1;
    }
  }
  return total;
}

int main(void)
{
  uint8_t pk[PK_BYTES], sk[SK_BYTES], ct[CT_BYTES];
  uint8_t ss0[SEED_BYTES], ss1[SEED_BYTES];
  uint8_t msg0[SEED_BYTES], msg1[SEED_BYTES];
  uint8_t kr[SEED_BYTES], reenc[CT_BYTES];
  uint8_t modified[CT_BYTES];
  size_t pos, bit;
  unsigned long tested = 0, invalid = 0, same_msg = 0, same_ss = 0;
  unsigned long first_invalid_same_msg = (unsigned long)-1;
  unsigned long first_invalid_pos = 0, first_invalid_bit = 0;
  unsigned long c2_effective = 0, c2_invalid = 0, c2_same_msg = 0;
  unsigned long c2_same_msg_hist[SEED_BYTES * 8 + 1] = {0};
  unsigned long c2_same_msg_onebit = 0;
  unsigned long trial_valid = 0, trial_invalid = 0;
  unsigned long trial_same_msg = 0, trial_same_ss = 0;

  if (mkem_keygen(pk, sk) != 0 || mkem_enc(pk, ss0, ct) != 0 ||
      mkem_dec(sk, ct, ss0) != 0) {
    fprintf(stderr, "keygen/encap/decap setup failed\n");
    return 2;
  }

  decap_parts(sk, ct, msg0, kr, reenc);
  if (verify(ct, reenc, CT_BYTES) != 0) {
    fprintf(stderr, "valid control did not re-encrypt\n");
    return 3;
  }

  for (pos = 0; pos < CT_BYTES; pos++) {
    for (bit = 0; bit < 8; bit++) {
      memcpy(modified, ct, CT_BYTES);
      modified[pos] ^= (uint8_t)(1u << bit);
      decap_parts(sk, modified, msg1, kr, reenc);
      if (verify(modified, reenc, CT_BYTES) == 0)
        continue;
      invalid++;
      if (pos >= CT_POLYVEC_COMPRESSED_BYTES) {
        unsigned d = bit_distance(msg0, msg1, SEED_BYTES);
        c2_effective++;
        c2_invalid++;
        c2_same_msg_hist[d]++;
        if (d == 1)
          c2_same_msg_onebit++;
      }
      if (memcmp(msg0, msg1, SEED_BYTES) == 0) {
        if (first_invalid_same_msg == (unsigned long)-1) {
          first_invalid_same_msg = tested;
          first_invalid_pos = pos;
          first_invalid_bit = bit;
        }
        same_msg++;
        if (pos >= CT_POLYVEC_COMPRESSED_BYTES)
          c2_same_msg++;
        mkem_dec(sk, modified, ss1);
        if (memcmp(ss0, ss1, SEED_BYTES) == 0)
          same_ss++;
      }
      tested++;
    }
  }

  printf("params=%d pk_bytes=%u sk_bytes=%u ct_bytes=%u seed_bytes=%u\n",
         PARAMS,
         (unsigned)PK_BYTES, (unsigned)SK_BYTES, (unsigned)CT_BYTES,
         (unsigned)SEED_BYTES);
  printf("valid_control_reencrypt=1 invalid_single_bit=%lu same_msg=%lu "
         "same_ss=%lu\n",
         invalid, same_msg, same_ss);
  printf("first_invalid_same_msg_pos=%lu bit=%u ss_equal=1\n",
         first_invalid_pos, (unsigned)first_invalid_bit);
  printf("c2_invalid=%lu c2_same_msg=%lu c2_msg_hamming_hist",
         c2_invalid, c2_same_msg);
  for (pos = 0; pos <= SEED_BYTES * 8; pos++)
    if (c2_same_msg_hist[pos])
      printf(" %lu:%lu", (unsigned long)pos, c2_same_msg_hist[pos]);
  printf("\n");
  printf("stored_z_offset=%u buggy_read_offset=%ld\n",
         (unsigned)(SK_BYTES - SEED_BYTES), (long)-SEED_BYTES);

  for (pos = 0; pos < TRIALS; pos++) {
    if (mkem_keygen(pk, sk) != 0 || mkem_enc(pk, ss0, ct) != 0 ||
        mkem_dec(sk, ct, ss1) != 0 || memcmp(ss0, ss1, SEED_BYTES) != 0)
      continue;
    trial_valid++;
    decap_parts(sk, ct, msg0, kr, reenc);
    if (verify(ct, reenc, CT_BYTES) != 0)
      continue;
    memcpy(modified, ct, CT_BYTES);
    modified[CT_BYTES - 1] ^= 1;
    decap_parts(sk, modified, msg1, kr, reenc);
    if (verify(modified, reenc, CT_BYTES) != 0)
      trial_invalid++;
    if (memcmp(msg0, msg1, SEED_BYTES) == 0)
      trial_same_msg++;
    mkem_dec(sk, modified, ss1);
    if (memcmp(ss0, ss1, SEED_BYTES) == 0)
      trial_same_ss++;
  }
  printf("trials_requested=%d trial_valid=%lu invalid_ct=%lu same_msg=%lu "
         "same_ss=%lu\n",
         TRIALS, trial_valid, trial_invalid, trial_same_msg, trial_same_ss);
  return same_msg == 0 || trial_valid == 0 || trial_same_ss != trial_valid;
}
