#include <stdio.h>
#include <string.h>

#include "/tmp/ngcc-harness-review.A5u9AZ/hash-25/TaiChi/Implementations/Reference_Implementation/TaiChi-512/CryptHash_AlgorithmInstance.c"

int main(void)
{
    unsigned char buf[176] = {0};
    uint64_t state[30] = {0};
    uint64_t A[22] = {0};
    uint64_t B[8] = {0};
    uint64_t S[22] = {0};
    uint64_t L[8] = {0};
    uint64_t R[8] = {0};
    uint64_t M[22] = {0};

    buf[0] = 0x80;
    buf[175] = 0x01;
    memcpy(M, buf, sizeof(buf));

    for (int i = 0; i < 22; i++) {
        state[i] = M[i];
    }
    state[29] ^= 0x02;
    printf("== INPUT\n");
    for (int i = 0; i < 30; i++) {
        printf("P %d %016llx\n", i, (unsigned long long)state[i]);
    }
    TaiChi_P1(state);
    memcpy(A, state, sizeof(A));
    memcpy(B, state + 22, sizeof(B));
    printf("== P1\n");
    for (int i = 0; i < 30; i++) {
        printf("P %d %016llx\n", i, (unsigned long long)state[i]);
    }
    for (int i = 0; i < 22; i++) {
        state[i] = A[i];
    }
    for (int i = 0; i < 8; i++) {
        state[22 + i] = R[i] ^ B[i];
    }
    printf("== P2 INPUT\n");
    for (int i = 0; i < 30; i++) {
        printf("P %d %016llx\n", i, (unsigned long long)state[i]);
    }
    TaiChi_P2(state);
    printf("== P2\n");
    for (int i = 0; i < 30; i++) {
        printf("P %d %016llx\n", i, (unsigned long long)state[i]);
    }

    TaiChi_Step(S, L, R, M, DOMAIN_FIN);

    for (int i = 0; i < 22; i++) {
        printf("S %d %016llx\n", i, (unsigned long long)S[i]);
    }
    for (int i = 0; i < 8; i++) {
        printf("L %d %016llx\n", i, (unsigned long long)L[i]);
    }
    for (int i = 0; i < 8; i++) {
        printf("R %d %016llx\n", i, (unsigned long long)R[i]);
    }
    return 0;
}
