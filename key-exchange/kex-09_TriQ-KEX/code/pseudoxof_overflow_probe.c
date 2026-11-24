#include <stdio.h>
#include <string.h>
#include "auxfunc.h"

int main(void)
{
    unsigned char msg[4] = {1, 2, 3, 4};
    unsigned char out[64] = {0};

    if (pseudoXOF(128, msg, sizeof(msg) * 8, out) != 0) {
        return 1;
    }
    printf("first byte: %02x\n", out[0]);
    return 0;
}
