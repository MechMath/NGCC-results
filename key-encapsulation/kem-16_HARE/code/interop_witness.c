#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "KEM_AlgorithmInstance.h"
#include "api.h"
#include "code.h"
#include "compression.h"
#include "gf2x.h"
#include "hqc.h"
#include "parameters.h"
#include "symmetric.h"
#include "vector.h"

/*
 * This is an independent transcription of HARE specification Algorithm 4.
 * The submitted implementation calls the same XOF sampler in the order
 * r2, e, r1; the specification calls it in the order e, r1, r2.
 */
static void spec_encrypt(ciphertext_pke_t *c_pke,
                         const uint8_t *ek_pke,
                         const uint8_t *m,
                         const uint8_t *theta) {
    shake256_xof_ctx theta_xof_ctx = {0};
    uint64_t h[VEC_N_SIZE_64] = {0};
    uint64_t s[VEC_N_SIZE_64] = {0};
    uint64_t r1[VEC_N_SIZE_64] = {0};
    uint64_t r2[VEC_N_SIZE_64] = {0};
    uint64_t e[VEC_N_SIZE_64] = {0};
    uint64_t tmp[VEC_N_SIZE_64] = {0};
    uint64_t v[VEC_N_SIZE_64] = {0};

    xof_init(&theta_xof_ctx, theta, SEED_BYTES);
    hqc_ek_pke_from_string(h, s, ek_pke);

    vect_sample_fixed_weight2(&theta_xof_ctx, e, PARAM_OMEGA_E);
    vect_sample_fixed_weight2(&theta_xof_ctx, r1, PARAM_OMEGA_R);
    vect_sample_fixed_weight2(&theta_xof_ctx, r2, PARAM_OMEGA_R);

    vect_mul(c_pke->u, r2, h);
    vect_add(c_pke->u, r1, c_pke->u, VEC_N_SIZE_64);

    code_encode(v, m);
    vect_mul(tmp, r2, s);
    vect_add(tmp, e, tmp, VEC_N_SIZE_64);
    vect_truncate(tmp);
    vect_add(v, v, tmp, VEC_N1N2_SIZE_64);
    ciphertext_compress(c_pke->m_tilde, c_pke->v2, v);
}

int main(void) {
    uint8_t seed[SEED_BYTES];
    uint8_t m[PARAM_K];
    uint8_t salt[SALT_BYTES];
    uint8_t sigma[PARAM_SECURITY_BYTES];
    uint8_t ek[PUBLIC_KEY_BYTES] = {0};
    uint8_t dk_pke[SEED_BYTES] = {0};
    uint8_t dk_kem[SECRET_KEY_BYTES] = {0};
    uint8_t hash_ek[SEED_BYTES] = {0};
    uint8_t k_theta[SHARED_SECRET_BYTES + SEED_BYTES] = {0};
    uint8_t theta[SEED_BYTES] = {0};
    uint8_t k_bar[SHARED_SECRET_BYTES] = {0};
    uint8_t recovered[PARAM_K] = {0};
    uint8_t decapped[SHARED_SECRET_BYTES] = {0};
    uint8_t c_kem[CIPHERTEXT_BYTES] = {0};
    ciphertext_pke_t c_impl = {0};
    ciphertext_pke_t c_spec = {0};
    ciphertext_kem_t c_kem_t = {0};
    int rc;

    for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = (uint8_t)(0x11u + i);
    for (size_t i = 0; i < sizeof(m); ++i) m[i] = (uint8_t)(0xA5u + i);
    for (size_t i = 0; i < sizeof(salt); ++i) salt[i] = (uint8_t)(0x3Cu + i);
    for (size_t i = 0; i < sizeof(sigma); ++i) sigma[i] = (uint8_t)(0x80u + i);

    hqc_pke_keygen(ek, dk_pke, seed);
    hash_h(hash_ek, ek);
    hash_g(k_theta, hash_ek, m, salt);
    memcpy(theta, k_theta + SHARED_SECRET_BYTES, SEED_BYTES);

    hqc_pke_encrypt(&c_impl, ek, m, theta);
    spec_encrypt(&c_spec, ek, m, theta);

    printf("impl_vs_spec_ciphertext_equal=%d\n",
           memcmp(&c_impl, &c_spec, sizeof(c_impl)) == 0);

    hqc_pke_decrypt(recovered, dk_pke, &c_spec);
    printf("spec_ciphertext_decrypts=%d\n", memcmp(m, recovered, sizeof(m)) == 0);

    c_kem_t.c_pke = c_spec;
    memcpy(c_kem_t.salt, salt, sizeof(salt));
    hqc_c_kem_to_string(c_kem, &c_kem_t);

    memcpy(dk_kem, ek, PUBLIC_KEY_BYTES);
    memcpy(dk_kem + PUBLIC_KEY_BYTES, dk_pke, SEED_BYTES);
    memcpy(dk_kem + PUBLIC_KEY_BYTES + SEED_BYTES, sigma, PARAM_SECURITY_BYTES);

    rc = crypto_kem_dec_status(decapped, c_kem, dk_kem);
    hash_j(k_bar, hash_ek, sigma, c_kem);

    printf("kem_dec_status=%d\n", rc);
    printf("decaps_returns_sender_key=%d\n",
           memcmp(decapped, k_theta, SHARED_SECRET_BYTES) == 0);
    printf("decaps_returns_implicit_rejection_key=%d\n",
           memcmp(decapped, k_bar, SHARED_SECRET_BYTES) == 0);
    return 0;
}
