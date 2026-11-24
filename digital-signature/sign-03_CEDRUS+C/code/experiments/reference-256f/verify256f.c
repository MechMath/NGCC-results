#include <stdio.h>
#include <stdlib.h>
#include "api.h"

static unsigned char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(2); }
    if (fseek(f, 0, SEEK_END) || (*n = (size_t)ftell(f), fseek(f, 0, SEEK_SET))) exit(2);
    unsigned char *p = malloc(*n ? *n : 1);
    if (!p || (*n && fread(p,1,*n,f) != *n)) exit(2);
    fclose(f);
    return p;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s PUBLIC_KEY MESSAGE SIGNATURE\n", argv[0]);
        return 2;
    }
    size_t pkn, mn, sn;
    unsigned char *pk = read_file(argv[1], &pkn);
    unsigned char *m = read_file(argv[2], &mn);
    unsigned char *s = read_file(argv[3], &sn);
    int rc = crypto_sign_verify(s, sn, m, mn, pk);
    printf("verify_rc=%d public_key_bytes=%zu message_bytes=%zu signature_bytes=%zu\n",
           rc, pkn, mn, sn);
    free(s); free(m); free(pk);
    return rc == 0 ? 0 : 1;
}
