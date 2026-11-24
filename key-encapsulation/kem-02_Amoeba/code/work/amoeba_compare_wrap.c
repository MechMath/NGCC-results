#include <stdint.h>

/*
 * Linker wrap used only as a spec-faithful control: compare every byte of
 * the re-encryption output, rather than every fourth byte.
 */
int32_t __wrap_cmp(uint8_t *c1, uint8_t *c2, int32_t len) {
    int32_t tag = 0;
    for (int32_t i = 0; i < len; i++) {
        tag |= (c1[i] != c2[i]);
    }
    return tag;
}
