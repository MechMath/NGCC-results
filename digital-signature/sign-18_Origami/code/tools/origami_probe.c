#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include ORIGAMI_SOURCE

static int read_exact(const char *path, unsigned char *buffer, size_t size) {
    FILE *stream = fopen(path, "rb");
    if (stream == NULL) return -1;
    size_t got = fread(buffer, 1, size, stream);
    int extra = fgetc(stream);
    fclose(stream);
    return got == size && extra == EOF ? 0 : -1;
}

static int verify_files(const char *pk_path, const char *message_path,
                        const char *signature_path) {
    unsigned char pk[BYTES_PK];
    unsigned char message[56];
    unsigned char signature[BYTES_SIGNATURE];
    unsigned char digest[BYTES_DIGEST];
    ph_expanded_PK expanded;
    if (read_exact(pk_path, pk, sizeof(pk)) != 0 ||
        read_exact(message_path, message, sizeof(message)) != 0 ||
        read_exact(signature_path, signature, sizeof(signature)) != 0) {
        return 1;
    }
    if (pseudohash(BYTES_DIGEST * 8, message, sizeof(message) * 8ULL, digest) != 0) {
        return 4;
    }
    if (ORIGAMI_NAMESPACE(pk_expand)(&expanded, pk) != 0) {
        return 2;
    }
    int result = ORIGAMI_NAMESPACE(verify)(
        &expanded, signature, digest, sizeof(digest));
    printf("%d\n", result);
    ORIGAMI_NAMESPACE(pk_free)(&expanded);
    return result == 0 ? 0 : 3;
}

static int hash_target_files(const char *message_path, const char *salt_path) {
    unsigned char message[56];
    unsigned char salt[BYTES_SALT];
    unsigned char digest[BYTES_DIGEST];
    gf_t target[ORIGAMI_M];
    if (read_exact(message_path, message, sizeof(message)) != 0 ||
        read_exact(salt_path, salt, sizeof(salt)) != 0) {
        return 1;
    }
    if (pseudohash(BYTES_DIGEST * 8, message, sizeof(message) * 8ULL, digest) != 0) {
        return 2;
    }
    hash_to_field(target, digest, sizeof(digest), salt);
    printf("T");
    for (int i = 0; i < ORIGAMI_M; i++) {
        printf(" %u", (unsigned)target[i]);
    }
    printf("\n");
    return 0;
}

static int dump_map(const char *pk_path, const char *message_path,
                    const char *signature_path) {
    unsigned char pk[BYTES_PK];
    unsigned char message[56];
    unsigned char signature[BYTES_SIGNATURE];
    unsigned char digest[BYTES_DIGEST];
    ph_expanded_PK expanded;
    gf_t target[ORIGAMI_M];
    residual_schedule_t schedule;
    if (read_exact(pk_path, pk, sizeof(pk)) != 0 ||
        read_exact(message_path, message, sizeof(message)) != 0 ||
        read_exact(signature_path, signature, sizeof(signature)) != 0) {
        return 1;
    }
    if (ORIGAMI_NAMESPACE(pk_expand)(&expanded, pk) != 0) {
        return 2;
    }
    if (pseudohash(BYTES_DIGEST * 8, message, sizeof(message) * 8ULL, digest) != 0) {
        return 3;
    }
    hash_to_field(target, digest, sizeof(digest), signature + BYTES_GF(ORIGAMI_N));

    printf("P");
    for (int i = 0; i < ORIGAMI_N; i++) {
        printf(" %u", (unsigned)expanded.secret_to_public[i]);
    }
    printf("\nT");
    for (int i = 0; i < ORIGAMI_M; i++) {
        printf(" %u", (unsigned)target[i]);
    }
    printf("\n");

    residual_schedule_init(&schedule, expanded.pk_seed);
    for (int zone = 0; zone < ORIGAMI_TOTAL_ZONES; zone++) {
        const zone_info_t *info = &g_zones[zone];
        const int non_oil_count = info->n_offset + info->flat_v;
        const int oil_start = info->n_offset + info->flat_v;
        const int64_t zone_base = eligible_affine_positions_before_zone(zone);
        for (int equation = 0; equation < info->flat_m; equation++) {
            gf_stream_t stream;
            const int global_equation = info->m_offset + equation;
            const int64_t equation_base = zone_base +
                (int64_t)equation * (int64_t)non_oil_count * (int64_t)info->flat_o;
            public_affine_stream_for_eq(&stream, expanded.pk_seed, global_equation);
            for (int non = 0; non < non_oil_count; non++) {
                for (int oil = 0; oil < info->flat_o; oil++) {
                    gf_t coefficient = gf_stream_next(&stream);
                    const int64_t index = equation_base +
                        (int64_t)non * (int64_t)info->flat_o + (int64_t)oil;
                    const long residual_rank = residual_rank_from_index(&schedule, index);
                    if (residual_rank >= 0) {
                        coefficient = expanded.R_coeffs[residual_rank];
                    }
                    if (coefficient != 0) {
                        printf("C %d %d %d %u\n", global_equation, non,
                               oil_start + oil, (unsigned)coefficient);
                    }
                }
            }
        }
    }
    ORIGAMI_NAMESPACE(pk_free)(&expanded);
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 5 && strcmp(argv[1], "verify") == 0) {
        return verify_files(argv[2], argv[3], argv[4]);
    }
    if (argc == 4 && strcmp(argv[1], "hash") == 0) {
        return hash_target_files(argv[2], argv[3]);
    }
    if (argc == 5 && strcmp(argv[1], "dump") == 0) {
        return dump_map(argv[2], argv[3], argv[4]);
    }
    fprintf(stderr,
            "usage: %s verify PK MSG SIG | hash MSG SALT | dump PK MSG SIG\n",
            argv[0]);
    return 64;
}
