#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "drng.h"
#include "sign.h"

DRNG_ctx drng_algorithm;

static int write_file(const char *path, const unsigned char *data, size_t len)
{
  FILE *f = fopen(path, "wb");
  if (f == NULL) {
    return -1;
  }
  if (fwrite(data, 1, len, f) != len) {
    fclose(f);
    return -1;
  }
  return fclose(f);
}

static int read_exact(const char *path, unsigned char *data, size_t len)
{
  unsigned char extra;
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    return -1;
  }
  if (fread(data, 1, len, f) != len) {
    fclose(f);
    return -1;
  }
  if (fread(&extra, 1, 1, f) != 0) {
    fclose(f);
    return -1;
  }
  return fclose(f);
}

static int generate(const char *outdir)
{
  unsigned char pk[RRLWR_SIGN_PK_LEN];
  unsigned char sk[RRLWR_SIGN_SK_LEN];
  unsigned char sig[RRLWR_SIGN_SIG_LEN];
  unsigned char msg[32];
  unsigned char seed[32] = {0};
  unsigned long long pk_len = 0;
  unsigned long long sk_len = 0;
  unsigned long long sig_len = 0;
  char pk_path[1024];
  char sig_path[1024];
  int self_verify;

  for (unsigned int i = 0; i < sizeof(msg); i++) {
    msg[i] = (unsigned char)i;
  }

  if (init_random_number(&drng_algorithm, seed, sizeof(seed)) != 0) {
    fprintf(stderr, "drng-init=failed\n");
    return 2;
  }
  if (sig_keygen(pk, &pk_len, sk, &sk_len) != 0) {
    fprintf(stderr, "keygen=failed\n");
    return 3;
  }
  if (sig_sign(sk, sk_len, msg, sizeof(msg), sig, &sig_len) != 0) {
    fprintf(stderr, "sign=failed\n");
    return 4;
  }
  self_verify = sig_verify(pk, pk_len, sig, sig_len, msg, sizeof(msg));

  snprintf(pk_path, sizeof(pk_path), "%s/pk.bin", outdir);
  snprintf(sig_path, sizeof(sig_path), "%s/sig.bin", outdir);
  if (write_file(pk_path, pk, sizeof(pk)) != 0 ||
      write_file(sig_path, sig, sizeof(sig)) != 0) {
    fprintf(stderr, "artifact-write=failed\n");
    return 5;
  }

  printf("profile=%d\n", RRLWR_SECURITY_LEVEL);
  printf("pk_len=%llu\n", pk_len);
  printf("sk_len=%llu\n", sk_len);
  printf("sig_len=%llu\n", sig_len);
  printf("seed=0000000000000000000000000000000000000000000000000000000000000000\n");
  printf("message=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n");
  printf("self_verify=%d\n", self_verify);
  return self_verify == 0 ? 0 : 6;
}

static int verify_saved(const char *pk_path, const char *sig_path)
{
  unsigned char pk[RRLWR_SIGN_PK_LEN];
  unsigned char sig[RRLWR_SIGN_SIG_LEN];
  unsigned char msg[32];
  unsigned long long pk_len = RRLWR_SIGN_PK_LEN;
  unsigned long long sig_len = RRLWR_SIGN_SIG_LEN;
  int verdict;

  for (unsigned int i = 0; i < sizeof(msg); i++) {
    msg[i] = (unsigned char)i;
  }
  if (read_exact(pk_path, pk, sizeof(pk)) != 0 ||
      read_exact(sig_path, sig, sizeof(sig)) != 0) {
    fprintf(stderr, "artifact-read=failed\n");
    return 2;
  }
  verdict = sig_verify(pk, pk_len, sig, sig_len, msg, sizeof(msg));
  printf("profile=%d\n", RRLWR_SECURITY_LEVEL);
  printf("verify=%d\n", verdict);
  return verdict == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
  if (argc == 3 && strcmp(argv[1], "generate") == 0) {
    return generate(argv[2]);
  }
  if (argc == 4 && strcmp(argv[1], "verify") == 0) {
    return verify_saved(argv[2], argv[3]);
  }
  fprintf(stderr, "usage: %s generate OUTDIR | verify PK SIG\n", argv[0]);
  return 64;
}
