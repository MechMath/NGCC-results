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
    const int hi = hex_nibble((unsigned char)text[2 * i]);
    const int lo = hex_nibble((unsigned char)text[2 * i + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (unsigned char)((hi << 4) | lo);
  }
  return 0;
}

static int parse_unsigned(const char *text, size_t *value) {
  char *end = NULL;
  const unsigned long parsed = strtoul(text, &end, 10);
  if (!end || *end != '\0') return -1;
  *value = (size_t)parsed;
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
  unsigned char msg[SIG_SN_BYTES + SIG_PK_BYTES];
  size_t pk_len = 0, sn_len = 0, msg_len = 0;
  size_t declared_msg_len = 0;
  size_t record_ordinal = 0;
  size_t records = 0;
  size_t accepted = 0;
  size_t rejected = 0;
  char line[32768];

  while (fgets(line, sizeof(line), f)) {
    line[strcspn(line, "\r\n")] = '\0';
    if (strncmp(line, "Count = ", 8) == 0) {
      size_t declared_count = 0;
      if (parse_unsigned(line + 8, &declared_count) != 0 ||
          declared_count != record_ordinal) {
        fprintf(stderr, "invalid Count at record %zu\n", record_ordinal);
        fclose(f);
        return 2;
      }
    } else if (strncmp(line, "PK = ", 5) == 0) {
      if (pk_len || decode_hex(pk, sizeof(pk), line + 5) != 0) {
        fprintf(stderr, "invalid PK at record %zu\n", record_ordinal);
        fclose(f);
        return 2;
      }
      pk_len = sizeof(pk);
    } else if (strncmp(line, "M_Len = ", 8) == 0) {
      if (declared_msg_len || parse_unsigned(line + 8, &declared_msg_len) != 0) {
        fprintf(stderr, "invalid M_Len at record %zu\n", record_ordinal);
        fclose(f);
        return 2;
      }
    } else if (strncmp(line, "M = ", 4) == 0) {
      if (msg_len || !declared_msg_len || declared_msg_len > sizeof(msg) ||
          decode_hex(msg, declared_msg_len, line + 4) != 0) {
        fprintf(stderr, "invalid M at record %zu\n", record_ordinal);
        fclose(f);
        return 2;
      }
      msg_len = declared_msg_len;
    } else if (strncmp(line, "Sn = ", 5) == 0) {
      if (sn_len || pk_len != sizeof(pk) || msg_len != declared_msg_len ||
          decode_hex(sn, sizeof(sn), line + 5) != 0) {
        fprintf(stderr, "invalid Sn at record %zu\n", record_ordinal);
        fclose(f);
        return 2;
      }
      sn_len = sizeof(sn);
      const int result =
          sig_verify(pk, pk_len, sn, sn_len, msg, msg_len);
      printf("record=%zu m_len=%zu verify_result=%d (%s)\n",
             record_ordinal, msg_len, result,
             result == 0 ? "accept" : "reject");
      ++records;
      if (result == 0) {
        ++accepted;
      } else {
        ++rejected;
      }
      ++record_ordinal;
      pk_len = 0;
      sn_len = 0;
      msg_len = 0;
      declared_msg_len = 0;
    }
  }
  fclose(f);

  if (pk_len || sn_len || msg_len || declared_msg_len) {
    fprintf(stderr, "incomplete final KAT record\n");
    return 2;
  }
  printf("summary records=%zu accepted=%zu rejected=%zu\n",
         records, accepted, rejected);
  return records && accepted == records ? 0 : 1;
}
