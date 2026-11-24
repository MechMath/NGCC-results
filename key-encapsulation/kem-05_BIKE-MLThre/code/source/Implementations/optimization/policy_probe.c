#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "kem.h"
#include "rng.h"

static int write_file(const char *path, const unsigned char *buf, size_t len)
{
  FILE *f = fopen(path, "wb");
  if(f == NULL) {
    fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
    return 1;
  }
  if((len != 0) && (fwrite(buf, 1, len, f) != len)) {
    fprintf(stderr, "fwrite(%s): %s\n", path, strerror(errno));
    fclose(f);
    return 1;
  }
  if(fclose(f) != 0) {
    fprintf(stderr, "fclose(%s): %s\n", path, strerror(errno));
    return 1;
  }
  return 0;
}

static int read_file(const char *path, unsigned char *buf, size_t len)
{
  FILE *f = fopen(path, "rb");
  if(f == NULL) {
    fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
    return 1;
  }
  if((len != 0) && (fread(buf, 1, len, f) != len)) {
    fprintf(stderr, "fread(%s): %s\n", path, strerror(errno));
    fclose(f);
    return 1;
  }
  if(fgetc(f) != EOF) {
    fprintf(stderr, "file %s is larger than expected %zu\n", path, len);
    fclose(f);
    return 1;
  }
  fclose(f);
  return 0;
}

static int write_variant(const char *dir, const char *name,
                         const unsigned char *ct)
{
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s.ct", dir, name);
  return write_file(path, ct, CRYPTO_CIPHERTEXTBYTES);
}

static int gen_case(const char *dir, unsigned seed_index)
{
  unsigned char entropy[48];
  unsigned char pk[CRYPTO_PUBLICKEYBYTES];
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  unsigned char ss[CRYPTO_BYTES];
  unsigned char mutated[CRYPTO_CIPHERTEXTBYTES];
  char path[1024];
  char name[64];

  for(size_t i = 0; i < sizeof(entropy); i++) {
    entropy[i] = (unsigned char)(0x5aU ^ (unsigned char)seed_index ^
                                (unsigned char)(i * 17U));
  }
  randombytes_init(entropy, NULL, 512);

  if((crypto_kem_keypair(pk, sk) != 0) ||
     (crypto_kem_enc(ct, ss, pk) != 0)) {
    fprintf(stderr, "keygen/enc failed for seed %u\n", seed_index);
    return 1;
  }

  snprintf(path, sizeof(path), "%s/case_%02u.pk", dir, seed_index);
  if(write_file(path, pk, sizeof(pk)) != 0) return 1;
  snprintf(path, sizeof(path), "%s/case_%02u.sk", dir, seed_index);
  if(write_file(path, sk, sizeof(sk)) != 0) return 1;
  snprintf(path, sizeof(path), "%s/case_%02u.ss", dir, seed_index);
  if(write_file(path, ss, sizeof(ss)) != 0) return 1;

  snprintf(name, sizeof(name), "case_%02u_valid", seed_index);
  if(write_variant(dir, name, ct) != 0) return 1;

  memcpy(mutated, ct, sizeof(ct));
  mutated[CRYPTO_CIPHERTEXTBYTES - 1] ^= 1U;
  snprintf(name, sizeof(name), "case_%02u_c1_bit0", seed_index);
  if(write_variant(dir, name, mutated) != 0) return 1;

  memcpy(mutated, ct, sizeof(ct));
  mutated[0] ^= 1U;
  snprintf(name, sizeof(name), "case_%02u_c0_bit0", seed_index);
  if(write_variant(dir, name, mutated) != 0) return 1;

  memcpy(mutated, ct, sizeof(ct));
  mutated[CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES - 1] ^= 1U;
  snprintf(name, sizeof(name), "case_%02u_c0_last", seed_index);
  if(write_variant(dir, name, mutated) != 0) return 1;

  memcpy(mutated, ct, sizeof(ct));
  {
    uint64_t x = 0x9e3779b97f4a7c15ULL ^
                 (0xd1b54a32d192ed03ULL * (uint64_t)(seed_index + 1U));
    const size_t c0_bytes = CRYPTO_CIPHERTEXTBYTES - CRYPTO_BYTES;
    for(unsigned int i = 0; i < 32U; i++) {
      x ^= x << 13;
      x ^= x >> 7;
      x ^= x << 17;
      const size_t bit = (size_t)(x % ((uint64_t)c0_bytes * 8U));
      mutated[bit >> 3] ^= (unsigned char)(1U << (bit & 7U));
    }
  }
  snprintf(name, sizeof(name), "case_%02u_c0_mask32", seed_index);
  if(write_variant(dir, name, mutated) != 0) return 1;

  printf("generated case_%02u pk_sha_input_bytes=%zu sk_bytes=%zu ct_bytes=%zu\n",
         seed_index, sizeof(pk), sizeof(sk), sizeof(ct));
  return 0;
}

static int dec_case(const char *sk_path, const char *ct_path,
                    const char *out_path)
{
  unsigned char sk[CRYPTO_SECRETKEYBYTES];
  unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
  unsigned char ss[CRYPTO_BYTES];
  if(read_file(sk_path, sk, sizeof(sk)) != 0) return 1;
  if(read_file(ct_path, ct, sizeof(ct)) != 0) return 1;
  if(crypto_kem_dec(ss, ct, sk) != 0) {
    fprintf(stderr, "crypto_kem_dec failed\n");
    return 1;
  }
  if(write_file(out_path, ss, sizeof(ss)) != 0) return 1;
  for(size_t i = 0; i < sizeof(ss); i++) {
    printf("%02x", ss[i]);
  }
  printf("\n");
  return 0;
}

int main(int argc, char **argv)
{
  if((argc == 4) && (strcmp(argv[1], "gen") == 0)) {
    char *end = NULL;
    unsigned long idx = strtoul(argv[3], &end, 10);
    if((end == argv[3]) || (*end != '\0') || (idx > 999U)) {
      fprintf(stderr, "bad seed index\n");
      return 2;
    }
    return gen_case(argv[2], (unsigned)idx);
  }
  if((argc == 5) && (strcmp(argv[1], "dec") == 0)) {
    return dec_case(argv[2], argv[3], argv[4]);
  }
  fprintf(stderr,
          "usage: %s gen DIR INDEX | dec SK CT OUTFILE\n"
          "compiled sizes: pk=%zu sk=%zu ct=%zu ss=%zu\n",
          argv[0], (size_t)CRYPTO_PUBLICKEYBYTES,
          (size_t)CRYPTO_SECRETKEYBYTES, (size_t)CRYPTO_CIPHERTEXTBYTES,
          (size_t)CRYPTO_BYTES);
  return 2;
}
