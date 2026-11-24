#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "parameters.h"
#include "sign.h"

#define MESSAGE_LEN 32

DRNG_ctx drng_algorithm;
static const unsigned char seed[32] = {0};
static const unsigned char message[MESSAGE_LEN] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static int write_exact(const char *path, const unsigned char *data, size_t len)
{
  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    perror(path);
    return -1;
  }
  if (fwrite(data, 1, len, f) != len) {
    perror(path);
    fclose(f);
    return -1;
  }
  if (fclose(f) != 0) {
    perror(path);
    return -1;
  }
  return 0;
}

static int read_exact(const char *path, unsigned char *data, size_t len)
{
  FILE *f = fopen(path, "rb");
  size_t got;
  if (f == NULL) {
    perror(path);
    return -1;
  }
  got = fread(data, 1, len, f);
  if (got != len) {
    fprintf(stderr, "%s: read %zu of %zu bytes\n", path, got, len);
    fclose(f);
    return -1;
  }
  if (fgetc(f) != EOF) {
    fprintf(stderr, "%s: trailing bytes\n", path);
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static int path_join(char *out, size_t out_len, const char *prefix, const char *name)
{
  int n = snprintf(out, out_len, "%s.%s", prefix, name);
  return n > 0 && (size_t)n < out_len ? 0 : -1;
}

static int generate(const char *prefix)
{
  DRNG_ctx drng;
  unsigned char pk[RRLWR_SIGN_PK_LEN];
  unsigned char sk[RRLWR_SIGN_SK_LEN];
  unsigned char sig[RRLWR_SIGN_SIG_LEN];
  unsigned long long pk_len = 0;
  unsigned long long sk_len = 0;
  unsigned long long sig_len = 0;
  char path[1024];

  if (init_random_number(&drng, seed, sizeof(seed)) != 0) {
    fprintf(stderr, "init_random_number failed\n");
    return 1;
  }
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
    fprintf(stderr, "sig_keygen failed\n");
    return 1;
  }
  if (sig_sign(sk, sk_len, (unsigned char *)message, MESSAGE_LEN, sig, &sig_len) != 0) {
    fprintf(stderr, "sig_sign failed\n");
    return 1;
  }
  if (pk_len != RRLWR_SIGN_PK_LEN || sk_len != RRLWR_SIGN_SK_LEN ||
      sig_len != RRLWR_SIGN_SIG_LEN) {
    fprintf(stderr, "unexpected output lengths: pk=%llu sk=%llu sig=%llu\n",
            pk_len, sk_len, sig_len);
    return 1;
  }

  if (path_join(path, sizeof(path), prefix, "pk") != 0 ||
      write_exact(path, pk, sizeof(pk)) != 0) {
    return 1;
  }
  if (path_join(path, sizeof(path), prefix, "sig") != 0 ||
      write_exact(path, sig, sizeof(sig)) != 0) {
    return 1;
  }
  printf("generated prefix=%s pk_len=%llu sk_len=%llu sig_len=%llu\n",
         prefix, pk_len, sk_len, sig_len);
  return 0;
}

static int verify(const char *prefix)
{
  unsigned char pk[RRLWR_SIGN_PK_LEN];
  unsigned char sig[RRLWR_SIGN_SIG_LEN];
  char path[1024];
  int verdict;

  if (path_join(path, sizeof(path), prefix, "pk") != 0 ||
      read_exact(path, pk, sizeof(pk)) != 0) {
    return 2;
  }
  if (path_join(path, sizeof(path), prefix, "sig") != 0 ||
      read_exact(path, sig, sizeof(sig)) != 0) {
    return 2;
  }

  verdict = sig_verify(pk, sizeof(pk), sig, sizeof(sig),
                       (unsigned char *)message, MESSAGE_LEN);
  printf("verify prefix=%s verdict=%d\n", prefix, verdict);
  return verdict == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
  if (argc != 3 ||
      (strcmp(argv[1], "generate") != 0 && strcmp(argv[1], "verify") != 0)) {
    fprintf(stderr, "usage: %s generate|verify <prefix>\n", argv[0]);
    return 64;
  }
  return strcmp(argv[1], "generate") == 0 ? generate(argv[2]) : verify(argv[2]);
}
