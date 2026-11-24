#include <stdio.h>
#include "/tmp/ngcc-harness-review.A5u9AZ/hash-25/TaiChi/Implementations/Reference_Implementation/TaiChi-512/CryptHash_AlgorithmInstance.c"

int main(void)
{
    uint64_t A[30] = {0};
    A[0] = 0x0000000000000080ULL;
    A[21] = 0x0100000000000000ULL;
    A[29] = 0x0000000000000002ULL;
    TaiChi_P1(A);
    for (int i = 0; i < 30; i++) {
        printf("%016llx\n", (unsigned long long)A[i]);
    }
    return 0;
}
