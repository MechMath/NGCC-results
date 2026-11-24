#include "sm4th_em_d2_128f_loose.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t decode_hex(const char *hex, uint8_t *out, size_t cap) {
  size_t n = strlen(hex);
  while (n && isspace((unsigned char)hex[n - 1])) --n;
  if ((n & 1u) || n / 2u > cap) return SIZE_MAX;
  for (size_t i = 0; i < n / 2u; ++i) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return SIZE_MAX;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return n / 2u;
}

int main(int argc, char **argv) {
  static const uint8_t pk[32] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      0xba, 0xae, 0xfc, 0x08, 0xb3, 0x97, 0xee, 0xec,
      0x0b, 0xd4, 0x88, 0x72, 0x1b, 0xe0, 0xe4, 0x5f,
  };
  if (argc != 2) return 2;
  FILE *f = fopen(argv[1], "r");
  if (!f) return 3;

  char *line = NULL;
  size_t cap = 0;
  uint8_t *msg = NULL;
  uint8_t *sig = NULL;
  size_t msg_len = 0;
  size_t sig_len = 0;
  while (getline(&line, &cap, f) >= 0) {
    if (strncmp(line, "message_hex=", 12) == 0) {
      msg = malloc(strlen(line));
      if (!msg) return 4;
      msg_len = decode_hex(line + 12, msg, strlen(line));
    } else if (strncmp(line, "signature_hex=", 14) == 0) {
      sig = malloc(strlen(line));
      if (!sig) return 5;
      sig_len = decode_hex(line + 14, sig, strlen(line));
    }
  }
  fclose(f);
  free(line);
  int accepted = msg && sig &&
                 sm4th_em_d2_128f_loose_verify(pk, msg, msg_len, sig, sig_len) == 0;
  printf("msg_len=%zu sig_len=%zu accepted=%d\n", msg_len, sig_len, accepted);
  free(msg);
  free(sig);
  return accepted ? 0 : 1;
}
