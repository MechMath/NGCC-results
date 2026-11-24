#ifndef AUDIT_TRIQ_PKE_H
#define AUDIT_TRIQ_PKE_H

#include <stdint.h>

typedef struct {
    uint8_t u[2038]; /* ceil(16301/8) */
    uint8_t v[2016]; /* 16128/8 */
} ciphertext_pke_t;

void triq_pke_keygen(uint8_t *ek_pke, uint8_t *dk_pke, uint8_t *seed);
void triq_pke_encrypt(ciphertext_pke_t *c_pke, const uint8_t *ek_pke,
                      const uint64_t *m, const uint8_t *theta);
uint8_t triq_pke_decrypt(uint64_t *m, const uint8_t *dk_pke,
                         const ciphertext_pke_t *c_pke);

#endif
