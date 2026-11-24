#include <stdint.h>
#include <stdio.h>
#include <string.h>

int crypto_stream_chacha20(
    unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *k) {
  (void)n;
  (void)k;
  memset(c, 0xff, (size_t)clen);
  return 0;
}

#include "/tmp/newhope-error.c"

int main(void) {
  poly x, xp, h;
  unsigned char kx[32], kxp[32], seed[32] = {0};
  memset(&x, 0, sizeof(x));
  memset(&xp, 0, sizeof(xp));

  x.coeffs[0] = 2877;
  x.coeffs[256] = 11013;
  x.coeffs[512] = 3420;
  x.coeffs[768] = 719;
  xp.coeffs[0] = 2063;
  xp.coeffs[256] = 8033;
  xp.coeffs[512] = 5801;
  xp.coeffs[768] = 10202;

  helprec(&h, &x, seed, 0);
  rec(kx, &x, &h);
  rec(kxp, &xp, &h);
  printf("h=%u,%u,%u,%u bits=%u,%u\n",
         h.coeffs[0], h.coeffs[256], h.coeffs[512], h.coeffs[768],
         kx[0] & 1, kxp[0] & 1);
  return 0;
}
