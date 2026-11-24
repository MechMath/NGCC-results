#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "drng.h"
#include "sign.h"

#define SEED_LEN_BYTES 64
#define MLEN 59
#define RECORD_BYTES (CRYPTO_PUBLICKEYBYTES + MLEN + CRYPTO_BYTES)

DRNG_ctx drng_algorithm;

static void make_case(unsigned long long i, uint8_t seed[SEED_LEN_BYTES],
                      uint8_t msg[MLEN], uint8_t pk[CRYPTO_PUBLICKEYBYTES],
                      uint8_t sk[CRYPTO_SECRETKEYBYTES]) {
  static DRNG_ctx drng_seed;
  static DRNG_ctx drng_msg;
  static int initialized;
  uint8_t nonce1[SEED_LEN_BYTES];
  uint8_t nonce2[SEED_LEN_BYTES];
  unsigned long long j;
  uint32_t counter = (uint32_t)i;

  if (!initialized) {
    for (j = 0; j + 4 <= SEED_LEN_BYTES; j += 4)
      memcpy(nonce1 + j, "seed", 4);
    for (j = 0; j + 3 <= SEED_LEN_BYTES; j += 3)
      memcpy(nonce2 + j, "msg", 3);
    nonce2[SEED_LEN_BYTES - 1] = (uint8_t)'m';
    init_random_number(&drng_seed, nonce1, SEED_LEN_BYTES);
    init_random_number(&drng_msg, nonce2, SEED_LEN_BYTES);
    initialized = 1;
  }

  get_random_number(&drng_seed, seed, SEED_LEN_BYTES * 8ULL);
  get_random_number(&drng_msg, msg, MLEN * 8ULL);
  memcpy(msg, &counter, sizeof(counter));
  init_random_number(&drng_algorithm, seed, SEED_LEN_BYTES);
  if (crypto_sign_keypair(pk, sk) != 0) {
    fprintf(stderr, "keypair failed at %llu\n", i);
    exit(2);
  }
}

static size_t write_record(FILE *out, unsigned long long i) {
  uint8_t seed[SEED_LEN_BYTES], msg[MLEN];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint8_t sig[CRYPTO_BYTES];
  size_t siglen = 0;

  make_case(i, seed, msg, pk, sk);
  if (crypto_sign_signature(sig, &siglen, msg, MLEN, NULL, 0, sk) != 0 ||
      siglen != CRYPTO_BYTES) {
    fprintf(stderr, "sign failed at %llu\n", i);
    exit(2);
  }
  if (fwrite(pk, 1, sizeof(pk), out) != sizeof(pk) ||
      fwrite(msg, 1, sizeof(msg), out) != sizeof(msg) ||
      fwrite(sig, 1, sizeof(sig), out) != sizeof(sig)) {
    fprintf(stderr, "write failed at %llu\n", i);
    exit(2);
  }
  return siglen;
}

static int read_record(FILE *in, uint8_t *rec) {
  return fread(rec, 1, RECORD_BYTES, in) == RECORD_BYTES;
}

int main(int argc, char **argv) {
  unsigned long long count, i;
  FILE *fp;

  if (argc != 4) {
    fprintf(stderr, "usage: %s generate COUNT FILE | compare COUNT FILE\n",
            argv[0]);
    return 1;
  }
  count = strtoull(argv[2], NULL, 10);

  if (strcmp(argv[1], "generate") == 0) {
    fp = fopen(argv[3], "wb");
    if (fp == NULL)
      return 2;
    for (i = 0; i < count; ++i)
      write_record(fp, i);
    fclose(fp);
    return 0;
  }

  if (strcmp(argv[1], "compare") == 0) {
    uint8_t foreign[RECORD_BYTES];
    fp = fopen(argv[3], "rb");
    if (fp == NULL)
      return 2;
    for (i = 0; i < count; ++i) {
      uint8_t seed[SEED_LEN_BYTES], msg[MLEN];
      uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
      uint8_t local_sig[CRYPTO_BYTES];
      size_t siglen;
      int own_ret, foreign_ret;

      if (!read_record(fp, foreign)) {
        fprintf(stderr, "short foreign file at %llu\n", i);
        return 2;
      }
      make_case(i, seed, msg, pk, sk);
      if (crypto_sign_signature(local_sig, &siglen, msg, MLEN, NULL, 0, sk) !=
          0) {
        fprintf(stderr, "local sign failed at %llu\n", i);
        return 2;
      }

      foreign_ret = crypto_sign_verify(foreign + CRYPTO_PUBLICKEYBYTES + MLEN,
                                       CRYPTO_BYTES,
                                       foreign + CRYPTO_PUBLICKEYBYTES, MLEN,
                                       NULL, 0, foreign);
      own_ret = crypto_sign_verify(local_sig, CRYPTO_BYTES, msg, MLEN, NULL, 0,
                                   pk);
      if (memcmp(foreign, pk, sizeof(pk)) != 0 ||
          memcmp(foreign + CRYPTO_PUBLICKEYBYTES, msg, MLEN) != 0 ||
          memcmp(foreign + CRYPTO_PUBLICKEYBYTES + MLEN, local_sig,
                 CRYPTO_BYTES) != 0) {
        printf("first_divergence index=%llu own_verify=%d foreign_verify=%d\n",
               i, own_ret, foreign_ret);
        printf("seed=");
        for (size_t k = 0; k < SEED_LEN_BYTES; ++k)
          printf("%02x", seed[k]);
        printf("\n");
        printf("msg=");
        for (size_t k = 0; k < MLEN; ++k)
          printf("%02x", msg[k]);
        printf("\n");
        printf("pk_sha_input_equal=%d msg_equal=%d sig_equal=%d\n",
               memcmp(foreign, pk, sizeof(pk)) == 0,
               memcmp(foreign + CRYPTO_PUBLICKEYBYTES, msg, MLEN) == 0,
               memcmp(foreign + CRYPTO_PUBLICKEYBYTES + MLEN, local_sig,
                      CRYPTO_BYTES) == 0);
        fclose(fp);
        return 3;
      }
      if (own_ret != 0 || foreign_ret != 0) {
        printf("verification_failure index=%llu own=%d foreign=%d\n", i,
               own_ret, foreign_ret);
        fclose(fp);
        return 4;
      }
    }
    fclose(fp);
    printf("identical_and_verified count=%llu\n", count);
    return 0;
  }
  return 1;
}
