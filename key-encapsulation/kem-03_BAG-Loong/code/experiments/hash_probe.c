#include <stdio.h>
#include <string.h>

#include "loong_hash.h"

static void print_hex(const char *name, const unsigned char *p, size_t n)
{
    size_t i;
    printf("%s=", name);
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

int main(void)
{
    unsigned char seed[32];
    unsigned char id_pk[32];
    unsigned char message[18];
    unsigned char salt[16];
    unsigned char xof[64];
    unsigned char g[64];
    size_t i;
    int rc;

    for (i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)i;
    for (i = 0; i < sizeof(id_pk); i++) id_pk[i] = (unsigned char)(0xa0 + i);
    for (i = 0; i < sizeof(message); i++) message[i] = (unsigned char)(0x30 + i);
    for (i = 0; i < sizeof(salt); i++) salt[i] = (unsigned char)(0xe0 + i);

    memset(xof, 0, sizeof(xof));
    rc = loong_xof_expand_public_seed(xof, sizeof(xof) * 8, seed, sizeof(seed));
    printf("public_seed_xof_rc=%d\n", rc);
    print_hex("public_seed_xof", xof, sizeof(xof));

    memset(g, 0, sizeof(g));
    rc = loong_hash_g(g, id_pk, sizeof(id_pk), message, sizeof(message),
                      salt, sizeof(salt));
    printf("g_rc=%d\n", rc);
    print_hex("g", g, sizeof(g));
    return rc == 0 ? 0 : 1;
}
