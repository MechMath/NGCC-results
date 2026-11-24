#include <stdio.h>
#include "params.h"
int main(void) {
  printf("%d %d %d\n", CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
         CRYPTO_BYTES);
  return 0;
}
