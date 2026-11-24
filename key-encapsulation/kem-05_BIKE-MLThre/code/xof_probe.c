#include <stdio.h>
#include <stdint.h>
#include "auxfunc.h"

int main(void)
{
    unsigned char msg[16] = {0};
    unsigned char out[32] = {0};
    int rc = pseudoXOF(sizeof(out) * 8ULL, msg, sizeof(msg) * 8ULL, out);
    printf("rc=%d out=", rc);
    for (size_t i = 0; i < sizeof(out); i++) {
        printf("%02x", out[i]);
    }
    printf("\n");
    return rc != 0;
}
