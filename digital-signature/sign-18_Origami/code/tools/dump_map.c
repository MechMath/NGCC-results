#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../source/Implementations and Test_Vectors/Implementations/Reference_Implementation/Origami-128/origami_ref.c"
#include "../source/Implementations and Test_Vectors/Implementations/Reference_Implementation/Origami-128/auxfunc.h"

static int read_file(const char *path, unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    size_t got = fread(buf, 1, len, f);
    int extra = fgetc(f);
    fclose(f);
    return got == len && extra == EOF ? 0 : -1;
}

int main(void) {
    unsigned char pk[BYTES_PK], msg[56], sig[BYTES_SIGNATURE], digest[BYTES_DIGEST];
    ph_expanded_PK pkx;
    gf_t target[ORIGAMI_M];
    residual_schedule_t rs;
    if (read_file("pk.bin", pk, sizeof(pk)) != 0 ||
        read_file("msg.bin", msg, sizeof(msg)) != 0 ||
        read_file("sig.bin", sig, sizeof(sig)) != 0) {
        fprintf(stderr, "input read failed\n");
        return 1;
    }
    if (ORIGAMI_NAMESPACE(pk_expand)(&pkx, pk) != 0) return 2;
    if (pseudohash(BYTES_DIGEST * 8, msg, sizeof(msg) * 8ULL, digest) != 0) return 3;
    hash_to_field(target, digest, sizeof(digest), sig + BYTES_GF(ORIGAMI_N));

    printf("P");
    for (int i = 0; i < ORIGAMI_N; i++)
        printf(" %u", (unsigned) pkx.secret_to_public[i]);
    printf("\nT");
    for (int i = 0; i < ORIGAMI_M; i++) printf(" %u", (unsigned) target[i]);
    printf("\n");

    residual_schedule_init(&rs, pkx.pk_seed);
    for (int zone = 0; zone < ORIGAMI_TOTAL_ZONES; zone++) {
        const zone_info_t *zn = &g_zones[zone];
        const int non_oil_count = zn->n_offset + zn->flat_v;
        const int oil_start = non_oil_count;
        const int64_t zone_base = eligible_affine_positions_before_zone(zone);
        for (int eq = 0; eq < zn->flat_m; eq++) {
            gf_stream_t gs;
            const int eq_global = zn->m_offset + eq;
            const int64_t eq_base = zone_base +
                (int64_t) eq * (int64_t) non_oil_count * (int64_t) zn->flat_o;
            public_affine_stream_for_eq(&gs, pkx.pk_seed, eq_global);
            for (int non = 0; non < non_oil_count; non++) {
                for (int oil_rel = 0; oil_rel < zn->flat_o; oil_rel++) {
                    gf_t coeff = gf_stream_next(&gs);
                    const int64_t idx = eq_base +
                        (int64_t) non * (int64_t) zn->flat_o + (int64_t) oil_rel;
                    const long rank = residual_rank_from_index(&rs, idx);
                    if (rank >= 0) coeff = pkx.R_coeffs[rank];
                    if (coeff != 0)
                        printf("C %d %d %d %u\n", eq_global, non,
                               oil_start + oil_rel, (unsigned) coeff);
                }
            }
        }
    }
    ORIGAMI_NAMESPACE(pk_free)(&pkx);
    return 0;
}
