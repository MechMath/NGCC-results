#include "SIG_AlgorithmInstance.h"
#include "drng.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DRNG_ctx drng_algorithm;

static int hex_nibble(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int decode_hex(unsigned char *out, size_t out_len, const char *text) {
  if (strlen(text) != 2 * out_len) return -1;
  for (size_t i = 0; i < out_len; ++i) {
    int hi = hex_nibble((unsigned char)text[2 * i]);
    int lo = hex_nibble((unsigned char)text[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s KAT_SIG.txt\n", argv[0]);
    return 2;
  }

  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 2;
  }

  unsigned char pk[SIG_PK_BYTES];
  unsigned char sn[SIG_SN_BYTES];
  unsigned char msg[4096];
  size_t pk_len = 0, sn_len = 0, msg_len = 0;
  char line[32768];

  while (fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (strncmp(line, "PK = ", 5) == 0) {
      if (pk_len || decode_hex(pk, sizeof(pk), line + 5) != 0) {
        fprintf(stderr, "invalid PK\n");
        return 2;
      }
      pk_len = sizeof(pk);
    } else if (strncmp(line, "Sn = ", 5) == 0) {
      if (sn_len || decode_hex(sn, sizeof(sn), line + 5) != 0) {
        fprintf(stderr, "invalid Sn\n");
        return 2;
      }
      sn_len = sizeof(sn);
      if (pk_len && msg_len) break;
    } else if (strncmp(line, "M = ", 4) == 0) {
      if (msg_len || decode_hex(msg, 56, line + 4) != 0) {
        fprintf(stderr, "invalid M\n");
        return 2;
      }
      msg_len = 56;
    }
  }
  fclose(f);

  if (pk_len != SIG_PK_BYTES || sn_len != SIG_SN_BYTES || msg_len != 56) {
    fprintf(stderr, "incomplete KAT record\n");
    return 2;
  }

  int result = sig_verify(pk, pk_len, sn, sn_len, msg, msg_len);
  printf("verify_result=%d (%s)\n", result, result == 0 ? "accept" : "reject");
  return result == 0 ? 0 : 1;
}
