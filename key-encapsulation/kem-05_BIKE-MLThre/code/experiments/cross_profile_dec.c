#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "api.h"
#include "kem.h"
#include "types.h"

static int hex_value(char c)
{
  if(c >= '0' && c <= '9') {
    return c - '0';
  }
  c = (char)toupper((unsigned char)c);
  if(c >= 'A' && c <= 'F') {
    return 10 + c - 'A';
  }
  return -1;
}

static int read_hex_field(FILE *f, const char *field, uint8_t *out, size_t cap,
                          size_t *out_len)
{
  char  *line = NULL;
  size_t line_cap = 0;
  ssize_t n;
  const size_t field_len = strlen(field);

  while((n = getline(&line, &line_cap, f)) >= 0) {
    if((size_t)n > field_len && strncmp(line, field, field_len) == 0) {
      const char *hex = line + field_len;
      size_t hex_len = strcspn(hex, "\r\n");
      if((hex_len & 1U) != 0 || hex_len / 2U > cap) {
        free(line);
        return -1;
      }
      for(size_t i = 0; i < hex_len / 2U; i++) {
        const int hi = hex_value(hex[2U * i]);
        const int lo = hex_value(hex[2U * i + 1U]);
        if(hi < 0 || lo < 0) {
          free(line);
          return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
      }
      *out_len = hex_len / 2U;
      free(line);
      return 0;
    }
  }
  free(line);
  return -1;
}

static void print_hex(const uint8_t *x, size_t n)
{
  for(size_t i = 0; i < n; i++) {
    printf("%02X", x[i]);
  }
}

static int convert_reference_128(const uint8_t ref_sk[2 * R_BYTES + M_BYTES],
                                 const uint8_t pk[R_BYTES], sk_t *sk)
{
  const uint8_t *h0 = ref_sk;
  const uint8_t *h1 = ref_sk + R_BYTES;
  const uint8_t *sigma = ref_sk + 2 * R_BYTES;
  size_t n0 = 0;
  size_t n1 = 0;

  memset(sk, 0, sizeof(*sk));
  memcpy(sk->bin[0].raw, h0, R_BYTES);
  memcpy(sk->bin[1].raw, h1, R_BYTES);
  memcpy(sk->pk.raw, pk, R_BYTES);
  memcpy(sk->sigma.raw, sigma, M_BYTES);

  for(uint32_t i = 0; i < R_BITS; i++) {
    if((h0[i / 8U] >> (i % 8U)) & 1U) {
      if(n0 >= D) {
        return -1;
      }
      sk->wlist[0].val[n0++] = i;
    }
    if((h1[i / 8U] >> (i % 8U)) & 1U) {
      if(n1 >= D) {
        return -1;
      }
      sk->wlist[1].val[n1++] = i;
    }
  }
  return (n0 == D && n1 == D) ? 0 : -1;
}

int main(int argc, char **argv)
{
  uint8_t ref_sk[2 * R_BYTES + M_BYTES] = {0};
  uint8_t pk[R_BYTES] = {0};
  uint8_t ct[R_BYTES + M_BYTES] = {0};
  uint8_t expected_ss[M_BYTES] = {0};
  uint8_t actual_ss[M_BYTES] = {0};
  size_t ref_sk_len = 0;
  size_t pk_len = 0;
  size_t ct_len = 0;
  size_t expected_ss_len = 0;
  FILE *f;
  sk_t sk;

  if(argc != 2) {
    fprintf(stderr, "usage: %s reference-KAT.txt\n", argv[0]);
    return 2;
  }
  f = fopen(argv[1], "rb");
  if(f == NULL) {
    perror("fopen");
    return 2;
  }

  if(read_hex_field(f, "PK = ", pk, sizeof(pk), &pk_len) != 0 ||
     read_hex_field(f, "SK = ", ref_sk, sizeof(ref_sk), &ref_sk_len) != 0 ||
     read_hex_field(f, "CT = ", ct, sizeof(ct), &ct_len) != 0 ||
     read_hex_field(f, "SS = ", expected_ss, sizeof(expected_ss),
                    &expected_ss_len) != 0) {
    fprintf(stderr, "failed to parse first vector\n");
    fclose(f);
    return 2;
  }
  fclose(f);

  if(pk_len != R_BYTES || ref_sk_len != sizeof(ref_sk) ||
     ct_len != sizeof(ct) || expected_ss_len != M_BYTES) {
    fprintf(stderr, "unexpected vector lengths\n");
    return 2;
  }
  if(convert_reference_128(ref_sk, pk, &sk) != 0) {
    fprintf(stderr, "reference key conversion failed\n");
    return 2;
  }

  const int rc = crypto_kem_dec(actual_ss, ct, (const uint8_t *)&sk);
  printf("dec_rc=%d\n", rc);
  printf("expected_ss=");
  print_hex(expected_ss, sizeof(expected_ss));
  printf("\nactual_ss=");
  print_hex(actual_ss, sizeof(actual_ss));
  printf("\nmatch=%d\n", memcmp(expected_ss, actual_ss, sizeof(actual_ss)) == 0);
  return (rc == 0 && memcmp(expected_ss, actual_ss, sizeof(actual_ss)) == 0) ?
           0 :
           1;
}
