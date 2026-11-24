#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "SIG_AlgorithmInstance.h"

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static unsigned char *parse_hex(const char *hex, size_t *out_len)
{
    size_t hex_len = strlen(hex);
    unsigned char *out;

    if ((hex_len & 1U) != 0) {
        return NULL;
    }
    out = malloc(hex_len / 2);
    if (out == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(out);
            return NULL;
        }
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = hex_len / 2;
    return out;
}

static void print_hex(const unsigned char *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    size_t pk_len = 0;
    size_t sk_len = 0;
    size_t sig_len = 0;
    unsigned char *pk;
    unsigned char *sk;
    unsigned char *sig;
    unsigned char short_msg[1] = {'A'};
    const uint64_t long_len = UINT64_C(0x100000001);
    unsigned char *long_msg;
    int short_result;
    int long_result;
    int mutated_sig_long_result;
    int changed_first_result;
    size_t rans_region_start = POLYC_PACKEDBYTES + POLYZ0L_PACKEDBYTES;
    uint16_t rans_len;
    size_t ignored_offset;

    if (argc != 3) {
        fprintf(stderr, "usage: %s PK_HEX SK_HEX\n", argv[0]);
        return 2;
    }
    pk = parse_hex(argv[1], &pk_len);
    sk = parse_hex(argv[2], &sk_len);
    if (pk == NULL || sk == NULL ||
        pk_len != sig_get_pk_len_bytes() ||
        sk_len != sig_get_sk_len_bytes()) {
        fprintf(stderr, "invalid or wrong-sized PK/SK\n");
        return 2;
    }

    sig_len = sig_get_sn_len_bytes();
    sig = malloc(sig_len);
    if (sig == NULL) {
        perror("malloc signature");
        return 2;
    }

    if (sig_sign(sk, sk_len, short_msg, 1, sig, &sig_len) != 0) {
        fprintf(stderr, "signing failed\n");
        return 2;
    }

    long_msg = mmap(NULL, (size_t)long_len, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (long_msg == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    long_msg[0] = 'A';
    long_msg[long_len - 1] = 'Z';

    short_result = sig_verify(pk, pk_len, sig, sig_len, short_msg, 1);
    long_result = sig_verify(pk, pk_len, sig, sig_len, long_msg, long_len);

    /*
     * The first fixed-size rANS region starts after cwave and the optional
     * z0 low part. Its first two bytes are the encoded byte count; bytes after
     * that prefix are fixed storage ignored by sigDecode.
     */
    memcpy(&rans_len, sig + rans_region_start, sizeof(rans_len));
    ignored_offset = rans_region_start + sizeof(rans_len) + rans_len;
    if (ignored_offset >= sig_len) {
        fprintf(stderr, "no ignored byte after first rANS segment\n");
        return 2;
    }
    sig[ignored_offset] ^= 0x01;
    mutated_sig_long_result =
        sig_verify(pk, pk_len, sig, sig_len, long_msg, long_len);

    long_msg[0] = 'B';
    changed_first_result = sig_verify(pk, pk_len, sig, sig_len, long_msg, long_len);

    printf("pk_len=%zu\n", pk_len);
    printf("sk_len=%zu\n", sk_len);
    printf("sig_len=%zu\n", sig_len);
    printf("short_len=1\n");
    printf("short_verify=%d\n", short_result);
    printf("long_len=%" PRIu64 "\n", long_len);
    printf("long_first=A\n");
    printf("long_last=Z\n");
    printf("long_verify=%d\n", long_result);
    printf("first_rans_region_start=%zu\n", rans_region_start);
    printf("first_rans_count=%u\n", (unsigned)rans_len);
    printf("changed_signature_offset=%zu\n", ignored_offset);
    printf("mutated_distinct_signature_long_verify=%d\n", mutated_sig_long_result);
    printf("changed_first_long_verify=%d\n", changed_first_result);
    printf("signature=");
    print_hex(sig, sig_len);

    munmap(long_msg, (size_t)long_len);
    free(sig);
    free(pk);
    free(sk);
    return (short_result == 0 &&
            long_result == 0 &&
            mutated_sig_long_result == 0 &&
            changed_first_result == 1)
               ? 0
               : 1;
}
