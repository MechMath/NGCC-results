#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "SIG_AlgorithmInstance.h"

#define CONTROL_MESSAGE_BYTES 16

static void die(const char *what)
{
    perror(what);
    exit(2);
}

static unsigned char *read_exact(const char *path, size_t expected)
{
    FILE *f = fopen(path, "rb");
    unsigned char *buf;
    int extra;

    if (f == NULL) {
        die(path);
    }
    buf = malloc(expected);
    if (buf == NULL) {
        die("malloc");
    }
    if (fread(buf, 1, expected, f) != expected) {
        fprintf(stderr, "%s: short read\n", path);
        exit(3);
    }
    extra = fgetc(f);
    if (extra != EOF) {
        fprintf(stderr, "%s: longer than expected %zu bytes\n", path, expected);
        exit(4);
    }
    fclose(f);
    return buf;
}

static int verify(const unsigned char *pk, const unsigned char *msg,
                  const unsigned char *sig)
{
    return sig_verify((unsigned char *)pk, SPX_PK_BYTES,
                      (unsigned char *)sig, SPX_BYTES,
                      (unsigned char *)msg, CONTROL_MESSAGE_BYTES);
}

int main(int argc, char **argv)
{
    unsigned char *pk;
    unsigned char *msg;
    unsigned char *sig;
    unsigned char *tmp;
    int rc_base_wrapper;
    int rc_base_direct;
    int rc_sig_flip;
    int rc_msg_flip;
    int rc_pk_flip;
    int rc_pub_root_flip;
    int rc_short_sig;
    int rc_declared_pk_len_zero;

    if (argc != 4) {
        fprintf(stderr, "usage: %s PK MSG SIG\n", argv[0]);
        return 1;
    }

    pk = read_exact(argv[1], SPX_PK_BYTES);
    msg = read_exact(argv[2], CONTROL_MESSAGE_BYTES);
    sig = read_exact(argv[3], SPX_BYTES);
    tmp = malloc(SPX_BYTES);
    if (tmp == NULL) {
        die("malloc");
    }

    rc_base_wrapper = verify(pk, msg, sig);
    rc_base_direct =
        crypto_sign_verify(sig, SPX_BYTES, msg, CONTROL_MESSAGE_BYTES, pk);

    memcpy(tmp, sig, SPX_BYTES);
    tmp[0] ^= 1;
    rc_sig_flip = verify(pk, msg, tmp);

    memcpy(tmp, msg, CONTROL_MESSAGE_BYTES);
    tmp[0] ^= 1;
    rc_msg_flip = verify(pk, tmp, sig);

    memcpy(tmp, pk, SPX_PK_BYTES);
    tmp[0] ^= 1;
    rc_pk_flip = verify(tmp, msg, sig);

    memcpy(tmp, pk, SPX_PK_BYTES);
    tmp[SPX_N] ^= 1;
    rc_pub_root_flip = verify(tmp, msg, sig);

    rc_short_sig = sig_verify((unsigned char *)pk, SPX_PK_BYTES,
                              (unsigned char *)sig, SPX_BYTES - 1,
                              (unsigned char *)msg, CONTROL_MESSAGE_BYTES);

    rc_declared_pk_len_zero =
        sig_verify((unsigned char *)pk, 0, (unsigned char *)sig, SPX_BYTES,
                   (unsigned char *)msg, CONTROL_MESSAGE_BYTES);

    printf("SPX_N=%u SPX_PK_BYTES=%u SPX_MSG_BYTES=%u SPX_BYTES=%u\n",
           (unsigned)SPX_N, (unsigned)SPX_PK_BYTES,
           (unsigned)CONTROL_MESSAGE_BYTES, (unsigned)SPX_BYTES);
    printf("rc_base_wrapper=%d\n", rc_base_wrapper);
    printf("rc_base_direct=%d\n", rc_base_direct);
    printf("rc_signature_bit0_flip=%d\n", rc_sig_flip);
    printf("rc_message_bit0_flip=%d\n", rc_msg_flip);
    printf("rc_public_key_bit0_flip=%d\n", rc_pk_flip);
    printf("rc_public_root_bit0_flip=%d\n", rc_pub_root_flip);
    printf("rc_short_signature=%d\n", rc_short_sig);
    printf("rc_declared_pk_len_zero=%d\n", rc_declared_pk_len_zero);

    free(tmp);
    free(sig);
    free(msg);
    free(pk);
    return 0;
}
