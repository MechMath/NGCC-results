#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

#include "drng.h"
#include "SIG_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int parse_hex(const char *hex, uint8_t **out, size_t *out_len) {
  size_t n = strlen(hex);
  if (n % 2 != 0) return -1;
  *out_len = n / 2;
  *out = calloc(*out_len ? *out_len : 1, 1);
  if (!*out) return -1;
  for (size_t i = 0; i < *out_len; ++i) {
    int hi = hex_nibble(hex[2 * i]);
    int lo = hex_nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    (*out)[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s <pk-hex> <signature-hex> <message-hex>\n", argv[0]);
    return 2;
  }
  uint8_t *pk = NULL, *sig = NULL, *msg = NULL;
  size_t pk_len = 0, sig_len = 0, msg_len = 0;
  if (parse_hex(argv[1], &pk, &pk_len) ||
      parse_hex(argv[2], &sig, &sig_len) ||
      parse_hex(argv[3], &msg, &msg_len)) {
    fprintf(stderr, "invalid hex input\n");
    return 2;
  }
  int verdict = sig_verify(pk, pk_len, sig, sig_len, msg, msg_len);
  struct rusage usage;
  if (getrusage(RUSAGE_SELF, &usage) != 0) {
    usage.ru_maxrss = 0;
  }
  printf("pk_bytes=%zu signature_bytes=%zu message_bytes=%zu verdict=%d (%s)\n",
         pk_len, sig_len, msg_len, verdict, verdict == 0 ? "ACCEPT" : "REJECT");
  printf("maxrss_kb=%ld\n", (long)usage.ru_maxrss);
  free(pk);
  free(sig);
  free(msg);
  return verdict == 0 ? 0 : 1;
}
