#ifndef AUDIT_PARSING_H
#define AUDIT_PARSING_H

#include <stdint.h>
#include "triq_pke.h"

typedef struct {
    ciphertext_pke_t c_pke;
    uint8_t salt[32];
} ciphertext_kem_t;

void triq_c_kem_to_string(uint8_t *ct, const ciphertext_kem_t *c_kem);
void triq_c_kem_from_string(ciphertext_pke_t *c_pke, uint8_t *salt,
                            const uint8_t *ct);

#endif
