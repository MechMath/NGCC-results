#include <stdint.h>
#include <stdio.h>

static const uint8_t S[32] = {
  0x1a,0x09,0x10,0x17,0x07,0x08,0x15,0x0e,
  0x19,0x1f,0x1e,0x0c,0x1b,0x01,0x04,0x0a,
  0x05,0x13,0x0d,0x0f,0x16,0x1c,0x06,0x18,
  0x11,0x12,0x14,0x03,0x1d,0x02,0x00,0x0b
};

static inline uint8_t apply(uint32_t A, uint8_t x) {
  uint8_t y = 0;
  while (x) {
    unsigned i = __builtin_ctz(x);
    y ^= (uint8_t)((A >> (5 * i)) & 31);
    x &= (uint8_t)(x - 1);
  }
  return y & 31;
}

static inline int invertible(uint32_t A) {
  uint32_t b = A;
  int rank = 0;
  for (int col = 0; col < 5; col++) {
    unsigned p = (unsigned)col * 5;
    uint32_t v = (b >> p) & 31;
    if (!v) continue;
    for (int j = col + 1; j < 5; j++) {
      unsigned q = (unsigned)j * 5;
      uint32_t w = (b >> q) & 31;
      uint32_t high = 1u << (4 - col);
      if ((v & high) && (w & high)) b ^= (uint64_t)v << q;
    }
    rank++;
  }
  return rank == 5;
}

int main(void) {
  uint64_t count = 0;
  for (uint32_t A = 0; A < (1u << 25); A++) {
    for (uint8_t bb = 0; bb < 32; bb++) {
      int ok = 1;
      for (uint8_t x = 0; x < 32; x++) {
        uint8_t axb = apply(A, x) ^ bb;
        if (S[axb] != (apply(A, S[x]) ^ bb)) { ok = 0; break; }
      }
      if (ok) {
        if (!invertible(A)) {
          fprintf(stderr, "noninvertible symmetry A=%08x b=%02x\n", A, bb);
          continue;
        }
        count++;
        printf("A=%08x b=%02x\n", A, bb);
        fflush(stdout);
      }
    }
  }
  fprintf(stderr, "count=%llu\n", (unsigned long long)count);
  return 0;
}
