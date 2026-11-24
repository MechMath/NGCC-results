#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "auxfunc.h"
#include "drng.h"
#include "parameters.h"
#include "symmetric.h"
#include "triq_pke.h"
#include "vector.h"

DRNG_ctx drng_algorithm;

typedef struct {
    uint16_t attempts;
    uint32_t first_support[PARAM_OMEGA_R];
    uint32_t accepted_support[PARAM_OMEGA_R];
    uint8_t accepted;
} bd_trace_t;

typedef struct {
    bd_trace_t r2;
    bd_trace_t r1;
} enc_trace_t;

typedef struct {
    uint32_t message_index;
    uint8_t message[PARAM_SECURITY_BYTES];
    uint8_t salt[SALT_BYTES];
    uint8_t h_ek[SEED_BYTES];
    uint8_t k_theta[SHARED_SECRET_BYTES + SEED_BYTES];
    uint8_t theta[SEED_BYTES];
    enc_trace_t trace;
    ciphertext_kem_t ciphertext;
} witness_t;

static void print_hex(FILE *out, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(out, "%02x", data[i]);
    }
}

static void print_support_array(FILE *out, const uint32_t *support, uint16_t weight) {
    fputc('[', out);
    for (uint16_t i = 0; i < weight; i++) {
        if (i != 0) {
            fputc(',', out);
        }
        fprintf(out, "%" PRIu32, support[i]);
    }
    fputc(']', out);
}

/*
 * This is the loop body of vect_sample_fixed_weight_bd, split out only so the
 * submitted vect_generate_random_support2 and vect_check_bounded_density
 * functions can be observed. The XOF advancement is therefore identical.
 */
static void trace_bounded_density(triq_xof_ctx *ctx, bd_trace_t *trace) {
    uint32_t support[PARAM_OMEGA_MAX] = {0};

    memset(trace, 0, sizeof(*trace));
    for (uint16_t iter = 0; iter < PARAM_BD_N_MAX; iter++) {
        vect_generate_random_support2(ctx, support, PARAM_OMEGA_R);
        if (iter == 0) {
            memcpy(trace->first_support, support, sizeof(trace->first_support));
        }
        trace->attempts = (uint16_t)(iter + 1);
        if (!vect_check_bounded_density(support, PARAM_OMEGA_R,
                                        PARAM_BD_L, PARAM_BD_GAMMA)) {
            memcpy(trace->accepted_support, support, sizeof(trace->accepted_support));
            trace->accepted = 1;
            return;
        }
    }

    /* The submitted routine retains the final rejected support on exhaustion. */
    memcpy(trace->accepted_support, support, sizeof(trace->accepted_support));
}

static void trace_encryption(const uint8_t theta[SEED_BYTES], enc_trace_t *trace) {
    triq_xof_ctx ctx = {0};
    uint64_t e[VEC_N_SIZE_64] = {0};

    memset(trace, 0, sizeof(*trace));
    xof_init(&ctx, theta, SEED_BYTES);
    trace_bounded_density(&ctx, &trace->r2);
    vect_sample_fixed_weight2(&ctx, e, PARAM_OMEGA_E);
    trace_bounded_density(&ctx, &trace->r1);
}

static void derive_message(uint32_t index, uint8_t message[PARAM_SECURITY_BYTES]) {
    memset(message, 0, PARAM_SECURITY_BYTES);
    message[PARAM_SECURITY_BYTES - 4] = (uint8_t)(index >> 24);
    message[PARAM_SECURITY_BYTES - 3] = (uint8_t)(index >> 16);
    message[PARAM_SECURITY_BYTES - 2] = (uint8_t)(index >> 8);
    message[PARAM_SECURITY_BYTES - 1] = (uint8_t)index;
}

static void fill_witness(witness_t *witness, uint32_t message_index,
                         const uint8_t h_ek[SEED_BYTES],
                         const uint8_t salt[SALT_BYTES]) {
    memset(witness, 0, sizeof(*witness));
    witness->message_index = message_index;
    derive_message(message_index, witness->message);
    memcpy(witness->salt, salt, SALT_BYTES);
    memcpy(witness->h_ek, h_ek, SEED_BYTES);
    hash_g(witness->k_theta, witness->h_ek, witness->message, witness->salt);
    memcpy(witness->theta,
           witness->k_theta + SHARED_SECRET_BYTES, SEED_BYTES);
    trace_encryption(witness->theta, &witness->trace);
}

static int same_trace(const enc_trace_t *a, const enc_trace_t *b) {
    return a->r2.attempts == b->r2.attempts &&
           a->r1.attempts == b->r1.attempts;
}

static int validate_witness(witness_t *witness,
                            const uint8_t pk[PUBLIC_KEY_BYTES],
                            const uint8_t sk[CRYPTO_SECRETKEYBYTES]) {
    uint8_t decrypted[PARAM_SECURITY_BYTES] = {0};
    uint8_t expected_key[SHARED_SECRET_BYTES] = {0};
    uint8_t recovered_key[SHARED_SECRET_BYTES] = {0};
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    uint8_t dk_pke[SEED_BYTES] = {0};
    ciphertext_pke_t dec_pke = {0};

    memcpy(dk_pke, sk + PUBLIC_KEY_BYTES, SEED_BYTES);
    triq_pke_encrypt(&witness->ciphertext.c_pke,
                     pk, (const uint64_t *)witness->message, witness->theta);
    memcpy(witness->ciphertext.salt, witness->salt, SALT_BYTES);
    triq_c_kem_to_string(ct, &witness->ciphertext);

    triq_c_kem_from_string(&dec_pke, decrypted, ct);
    if (triq_pke_decrypt((uint64_t *)decrypted, dk_pke, &dec_pke) != 0) {
        return 0;
    }
    if (memcmp(decrypted, witness->message, PARAM_SECURITY_BYTES) != 0) {
        return 0;
    }

    memcpy(expected_key, witness->k_theta, SHARED_SECRET_BYTES);
    if (crypto_kem_dec(recovered_key, ct, sk) != 0) {
        return 0;
    }
    return memcmp(expected_key, recovered_key, SHARED_SECRET_BYTES) == 0;
}

static void write_bd_json(FILE *out, const char *name, const bd_trace_t *trace) {
    fprintf(out, "    \"%s\": {\"attempts\": %u, \"accepted\": %u, ", name,
            trace->attempts, trace->accepted);
    fputs("\"first_support\": ", out);
    print_support_array(out, trace->first_support, PARAM_OMEGA_R);
    fputs(", \"accepted_support\": ", out);
    print_support_array(out, trace->accepted_support, PARAM_OMEGA_R);
    fputs("}", out);
}

static void write_witness_json(FILE *out, const witness_t *witness,
                               int last) {
    fprintf(out, "  {\n");
    fprintf(out, "    \"message_index\": %" PRIu32 ",\n", witness->message_index);
    fputs("    \"message_hex\": \"", out);
    print_hex(out, witness->message, PARAM_SECURITY_BYTES);
    fputs("\",\n    \"salt_hex\": \"", out);
    print_hex(out, witness->salt, SALT_BYTES);
    fputs("\",\n    \"h_ek_hex\": \"", out);
    print_hex(out, witness->h_ek, SEED_BYTES);
    fputs("\",\n    \"k_theta_hex\": \"", out);
    print_hex(out, witness->k_theta, sizeof(witness->k_theta));
    fputs("\",\n    \"theta_hex\": \"", out);
    print_hex(out, witness->theta, SEED_BYTES);
    fputs("\",\n    \"ciphertext_sha256_input_path\": \"artifacts/witness_", out);
    fprintf(out, "%" PRIu32 "_ct.bin", witness->message_index);
    fputs("\",\n    \"trace\": {\n", out);
    write_bd_json(out, "r2", &witness->trace.r2);
    fputs(",\n", out);
    write_bd_json(out, "r1", &witness->trace.r1);
    fputs("\n    }\n  }", out);
    if (!last) {
        fputc(',', out);
    }
    fputc('\n', out);
}

static int write_ciphertext(const witness_t *witness) {
    char path[128];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {0};
    FILE *out;

    snprintf(path, sizeof(path), "artifacts/witness_%" PRIu32 "_ct.bin",
             witness->message_index);
    triq_c_kem_to_string(ct, &witness->ciphertext);
    out = fopen(path, "wb");
    if (out == NULL) {
        return 0;
    }
    if (fwrite(ct, 1, sizeof(ct), out) != sizeof(ct)) {
        fclose(out);
        return 0;
    }
    return fclose(out) == 0;
}

int main(void) {
    uint8_t entropy[48];
    uint8_t personalization[48];
    uint8_t pk[PUBLIC_KEY_BYTES] = {0};
    uint8_t sk[CRYPTO_SECRETKEYBYTES] = {0};
    uint8_t h_ek[SEED_BYTES] = {0};
    uint8_t salt[SALT_BYTES] = {0};
    witness_t first;
    witness_t second;
    int have_first = 0;
    int have_second = 0;
    uint64_t examined = 0;
    FILE *out;

    for (size_t i = 0; i < sizeof(entropy); i++) {
        entropy[i] = (uint8_t)(0xa0U + i);
        personalization[i] = (uint8_t)(0x10U + i);
    }
    prng_init(entropy, personalization, sizeof(entropy), sizeof(personalization));
    if (crypto_kem_keypair(pk, sk) != 0) {
        fputs("key generation failed\n", stderr);
        return 1;
    }
    hash_h(h_ek, pk);

    /*
     * Sampling frame: all 2^16 messages with 12 leading zero bytes and the
     * final four bytes the big-endian counter, with one fixed all-zero salt.
     * Stop as soon as two message-derived traces have different attempt counts.
     */
    for (uint32_t index = 0; index < (1U << 16); index++) {
        witness_t current;
        fill_witness(&current, index, h_ek, salt);
        examined++;
        if (!have_first) {
            first = current;
            have_first = 1;
            continue;
        }
        if (!same_trace(&first.trace, &current.trace)) {
            second = current;
            have_second = 1;
            break;
        }
    }

    if (!have_second) {
        fprintf(stderr,
                "no differing pair found after exhaustive 2^16 frame; examined=%" PRIu64 "\n",
                examined);
        return 2;
    }

    if (!validate_witness(&first, pk, sk) ||
        !validate_witness(&second, pk, sk)) {
        fputs("static-KEM/PKE validation failed\n", stderr);
        return 3;
    }
    if (!write_ciphertext(&first) || !write_ciphertext(&second)) {
        fputs("ciphertext artifact write failed\n", stderr);
        return 4;
    }

    out = fopen("artifacts/pk128.bin", "wb");
    if (out == NULL || fwrite(pk, 1, sizeof(pk), out) != sizeof(pk) ||
        fclose(out) != 0) {
        fputs("public-key artifact write failed\n", stderr);
        return 5;
    }

    out = fopen("artifacts/witness128.json", "w");
    if (out == NULL) {
        fputs("witness JSON open failed\n", stderr);
        return 6;
    }
    fputs("{\n", out);
    fputs("  \"profile\": \"TriQ-KEX-128 static KEM re-encryption\",\n", out);
    fputs("  \"parameters\": {\"n\": 16301, \"weight_r\": 67, \"weight_e\": 106, ", out);
    fputs("\"bounded_density_L\": 384, \"bounded_density_gamma\": 7, ", out);
    fputs("\"sampler_N_max\": 256, \"message_bytes\": 16, \"salt_bytes\": 32},\n", out);
    fputs("  \"sampling_frame\": \"all 2^16 big-endian message counters in the last four bytes, 12 leading zero bytes, fixed all-zero salt; stop at first differing pair\",\n", out);
    fprintf(out, "  \"messages_examined\": %" PRIu64 ",\n", examined);
    fputs("  \"public_key_path\": \"artifacts/pk128.bin\",\n", out);
    fputs("  \"public_key_prefix_hex\": \"", out);
    print_hex(out, pk, 64);
    fputs("\",\n  \"h_ek_hex\": \"", out);
    print_hex(out, h_ek, sizeof(h_ek));
    fputs("\",\n  \"ciphertext_bytes\": 4086,\n", out);
    fputs("  \"validation\": \"PKE plaintext round trip and crypto_kem_dec accepted both ciphertexts and recovered the expected K\",\n", out);
    fputs("  \"witnesses\": [\n", out);
    write_witness_json(out, &first, 0);
    write_witness_json(out, &second, 1);
    fputs("  ]\n}\n", out);
    if (fclose(out) != 0) {
        return 7;
    }

    printf("messages_examined=%" PRIu64 "\n", examined);
    printf("witness0 index=%" PRIu32 " r2=%u r1=%u\n",
           first.message_index, first.trace.r2.attempts, first.trace.r1.attempts);
    printf("witness1 index=%" PRIu32 " r2=%u r1=%u\n",
           second.message_index, second.trace.r2.attempts, second.trace.r1.attempts);
    return 0;
}
