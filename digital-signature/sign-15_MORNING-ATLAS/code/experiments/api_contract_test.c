#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "drng.h"
#include "params.h"

DRNG_ctx drng_algorithm;

static unsigned char *read_file(const char *path, size_t *len)
{
  FILE *f = fopen(path, "rb");
  unsigned char *p;
  long n;

  if (f == NULL) return NULL;
  if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
      fseek(f, 0, SEEK_SET) != 0) {
    fclose(f);
    return NULL;
  }
  p = malloc((size_t)n);
  if (p == NULL || fread(p, 1, (size_t)n, f) != (size_t)n) {
    free(p);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return p;
}

int main(void)
{
  size_t pk_len, sk_len, m_len, fixture_len;
  unsigned char *pk = read_file("experiments/kat128_count0/pk.bin", &pk_len);
  unsigned char *sk = read_file("experiments/kat128_count0/sk.bin", &sk_len);
  unsigned char *m = read_file("experiments/kat128_count0/m.bin", &m_len);
  unsigned char *fixture = read_file("experiments/kat128_count0/sn.bin", &fixture_len);
  unsigned char *sign_buffer = NULL;
  unsigned char *out = NULL;
  unsigned char *inplace = NULL;
  unsigned long long reported_len = 0;
  int sign_rt;
  int output_only_rt;
  int prefilled_rt;
  int inplace_rt;
  int prefilled_generated_rt;
  int suffix_preserved = 0;
  int fixture_suffix_matches_message = 0;

  if (pk == NULL || sk == NULL || m == NULL || fixture == NULL ||
      pk_len != CRYPTO_PUBLICKEYBYTES ||
      sk_len != CRYPTO_SECRETKEYBYTES ||
      fixture_len != CRYPTO_BYTES + m_len) {
    fprintf(stderr, "fixture size/read error\n");
    return 2;
  }

  fixture_suffix_matches_message =
      memcmp(fixture + CRYPTO_BYTES, m, m_len) == 0;

  out = malloc(m_len);
  inplace = malloc(fixture_len);
  sign_buffer = malloc(CRYPTO_BYTES + m_len);
  if (out == NULL || inplace == NULL || sign_buffer == NULL) return 2;

  memset(out, 0xa5, m_len);
  output_only_rt = sig_verify(pk, pk_len,
                              fixture, fixture_len, out, m_len);

  memcpy(out, m, m_len);
  prefilled_rt = sig_verify(pk, pk_len,
                            fixture, fixture_len, out, m_len);

  memcpy(inplace, fixture, fixture_len);
  inplace_rt = sig_verify(pk, pk_len,
                          inplace, fixture_len, inplace, m_len);

  /*
   * The KAT public key is not stored in the private-key file, so derive a
   * matching public key by rerunning key generation from the KAT-0 seed in
   * the separate malleability harness. Here we exercise only sign's output
   * contract by using the fixture secret key and marker-filled output.
   */
  memset(sign_buffer, 0xa5, CRYPTO_BYTES + m_len);
  sign_rt = sig_sign(sk, sk_len, m, m_len, sign_buffer, &reported_len);
  if (sign_rt == 0) {
    size_t i;
    suffix_preserved = 1;
    for (i = 0; i < m_len; ++i)
      if (sign_buffer[CRYPTO_BYTES + i] != 0xa5) suffix_preserved = 0;
  }

  memcpy(out, m, m_len);
  prefilled_generated_rt = sig_verify(pk, pk_len,
                                      sign_buffer, reported_len, out, m_len);

  printf("fixture_len=%zu message_len=%zu reported_sign_len=%llu\n",
         fixture_len, m_len, reported_len);
  printf("fixture_suffix_matches_message=%d\n",
         fixture_suffix_matches_message);
  printf("output_only_verify=%d prefilled_message_verify=%d in_place_verify=%d\n",
         output_only_rt, prefilled_rt, inplace_rt);
  printf("sign_rt=%d sign_suffix_preserved_marker=%d\n",
         sign_rt, suffix_preserved);
  printf("generated_signature_prefilled_verify=%d\n", prefilled_generated_rt);

  free(sign_buffer);
  free(inplace);
  free(out);
  free(fixture);
  free(m);
  free(sk);
  free(pk);
  return 0;
}
