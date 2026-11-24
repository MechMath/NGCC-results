#include <stdio.h>
#include <stdint.h>
#include "align.h"
#include "params.h"
#include "rounding.h"

int main(void) {
  ALIGNED_INT32(N) in, hi, lo;
  unsigned long long found = 0;
  for (unsigned long long base = 0; base < Q; base += N) {
    for (unsigned i = 0; i < N; ++i)
      in.coeffs[i] = (int32_t)((base + i) % Q);
    decompose_avx(hi.vec, lo.vec, in.vec);
    for (unsigned i = 0; i < N; ++i) {
      int32_t scalar_lo;
      int32_t scalar_hi = decompose(&scalar_lo, in.coeffs[i]);
      if (scalar_hi != hi.coeffs[i] || scalar_lo != lo.coeffs[i]) {
        printf("input=%d scalar_hi=%d avx_hi=%d scalar_lo=%d avx_lo=%d po2=%d\n",
               in.coeffs[i], scalar_hi, hi.coeffs[i], scalar_lo,
               lo.coeffs[i], 2 * GAMMA2);
        if (++found == 20)
          return 3;
      }
    }
  }
  printf("all_equal\n");
  return 0;
}
