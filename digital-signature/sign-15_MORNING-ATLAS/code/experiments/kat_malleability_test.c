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

  if (f == NULL) {
    perror(path);
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 || fseek(f, 0, SEEK_SET) != 0) {
    perror("fseek/ftell");
    fclose(f);
    return NULL;
  }
  p = malloc((size_t)n);
  if (p == NULL || fread(p, 1, (size_t)n, f) != (size_t)n) {
    fprintf(stderr, "read failed: %s\n", path);
    free(p);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *len = (size_t)n;
  return p;
}

int main(int argc, char **argv)
{
  size_t pk_len, sn_len, m_len;
  unsigned char *pk = read_file(argc > 1 ? argv[1] : "experiments/kat128_count0/pk.bin", &pk_len);
  unsigned char *sn = read_file(argc > 2 ? argv[2] : "experiments/kat128_count0/sn.bin", &sn_len);
  unsigned char *m = read_file(argc > 3 ? argv[3] : "experiments/kat128_count0/m.bin", &m_len);
  unsigned char *altered = NULL;
  unsigned char *recovered = NULL;
  const size_t z_bytes = (size_t)L * POLZ_SIZE_PACKED;
  const size_t hint_bytes = OMEGA + K;
  const size_t c_mask_bytes = N / 8;
  const size_t unused_sign_byte = z_bytes + hint_bytes + c_mask_bytes + 3;
  const size_t used_sign_byte = z_bytes + hint_bytes + c_mask_bytes;
  unsigned int hint_count;
  size_t padding_offset = 0;
  int base_rt, unused_rt, used_rt, padding_rt = -1;

  if (pk == NULL || sn == NULL || m == NULL) return 2;
  if (pk_len != CRYPTO_PUBLICKEYBYTES || sn_len != CRYPTO_BYTES + m_len) {
    fprintf(stderr, "unexpected sizes pk=%zu sn=%zu m=%zu\n", pk_len, sn_len, m_len);
    return 2;
  }
  altered = malloc(sn_len);
  recovered = malloc(m_len);
  if (altered == NULL || recovered == NULL) return 2;

  memcpy(recovered, m, m_len);
  base_rt = sig_verify(pk, pk_len, sn, sn_len, recovered, m_len);
  printf("base_verify=%d recovered_matches=%d\n",
         base_rt, memcmp(recovered, m, m_len) == 0);

  memcpy(altered, sn, sn_len);
  altered[unused_sign_byte] ^= 0x80; /* sign bit 31 is unused when KAPPA=31 */
  memcpy(recovered, m, m_len);
  unused_rt = sig_verify(pk, pk_len, altered, sn_len, recovered, m_len);

  memcpy(altered, sn, sn_len);
  altered[used_sign_byte] ^= 0x01; /* sign bit 0 is part of this challenge */
  memcpy(recovered, m, m_len);
  used_rt = sig_verify(pk, pk_len, altered, sn_len, recovered, m_len);

  hint_count = sn[z_bytes + OMEGA + K - 1];
  if (hint_count < OMEGA) {
    padding_offset = z_bytes + hint_count;
    memcpy(altered, sn, sn_len);
    altered[padding_offset] ^= 0x01;
    memcpy(recovered, m, m_len);
    padding_rt = sig_verify(pk, pk_len, altered, sn_len, recovered, m_len);
  }

  printf("n=%u k=%u l=%u kappa=%u omega=%u sig=%u msg=%zu z_bytes=%zu hint_bytes=%zu\n",
         N, K, L, KAPPA, OMEGA, CRYPTO_BYTES, m_len, z_bytes, hint_bytes);
  printf("unused_sign_offset=%zu hint_count=%u hint_padding_offset=%zu\n",
         unused_sign_byte, hint_count, padding_offset);
  printf("unused_sign_flip_verify=%d used_sign_flip_verify=%d hint_padding_flip_verify=%d\n",
         unused_rt, used_rt, padding_rt);

  free(recovered);
  free(altered);
  free(m);
  free(sn);
  free(pk);

  if (base_rt != 0) return 3;
  if (unused_rt != 0 || padding_rt != 0 || used_rt == 0) return 4;
  return 0;
}
