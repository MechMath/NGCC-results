#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "api.h"
#include "counters.h"
#include "drng.h"
#include "hash.h"

DRNG_ctx drng_algorithm;

static void die(const char *s) { fprintf(stderr, "fatal: %s: %s\n", s, strerror(errno)); exit(2); }
static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec/1e9; }

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s FIRST_QUERY COUNT OUTDIR\n", argv[0]);
        return 2;
    }
    unsigned first = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned count = (unsigned)strtoul(argv[2], NULL, 10);
    const char *outdir = argv[3];
    char path[512];
    snprintf(path, sizeof(path), "%s/query-log.tsv", outdir);
    FILE *log = fopen(path, "wb");
    if (!log) die(path);
    fprintf(log, "query\tmessage\tsign_rc\tsiglen\tsha256_prefix\n");

    unsigned char seed[CRYPTO_SEEDBYTES];
    unsigned char drng_seed[64];
    for (size_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(0x40 + (i*17)%191);
    for (size_t i = 0; i < sizeof(drng_seed); i++) drng_seed[i] = (unsigned char)(0x31 + i*13 + first);
    if (init_random_number(&drng_algorithm, drng_seed, sizeof(drng_seed))) return 2;
    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    if (crypto_sign_seed_keypair(pk, sk, seed)) return 2;
    snprintf(path, sizeof(path), "%s/public-key.bin", outdir);
    FILE *pf = fopen(path, "wb"); if (!pf) die(path);
    if (fwrite(pk,1,sizeof(pk),pf) != sizeof(pk) || fclose(pf)) die("public key write");
    spx_ctx ctx; memset(&ctx,0,sizeof(ctx)); memcpy(ctx.pub_seed,pk,SPX_N); initialize_hash_function(&ctx);

    unsigned char *sig = malloc(CRYPTO_BYTES); if (!sig) die("sig");
    unsigned target = 0, owned = 0, failed = 0;
    double start = now();
    for (unsigned k = 0; k < count; k++) {
        unsigned q = first + k;
        char msg[128]; int n = snprintf(msg,sizeof(msg),"ordinary-query-256f-%06u",q);
        size_t slen = 0;
        int rc = crypto_sign_signature(sig,&slen,(const unsigned char*)msg,(size_t)n,sk);
        if (rc || slen != CRYPTO_BYTES) { failed++; fprintf(log,"%u\t%s\t%d\t%zu\t-\n",q,msg,rc,slen); continue; }
        uint32_t counter = get_fors_counter(sig), c = counter;
        unsigned char digest[SPX_FORS_MSG_BYTES]; uint64_t tree; uint32_t leaf;
        int hrc = hash_message(digest,&tree,&leaf,sig,pk,(const unsigned char*)msg,(size_t)n,&ctx,&c);
        if (hrc == 0 && tree == 0 && leaf == 0) {
            snprintf(path,sizeof(path),"%s/record-%06u.bin",outdir,q);
            FILE *rf = fopen(path,"wb"); if (!rf) die(path);
            if (fwrite(sig,1,CRYPTO_BYTES,rf) != CRYPTO_BYTES || fclose(rf)) die("record");
            target++; owned++;
        }
        fprintf(log,"%u\t%s\t%d\t%zu\t%s\n",q,msg,rc,slen,
                (hrc == 0 && tree == 0 && leaf == 0) ? "retained" : "other-instance");
    }
    fclose(log);
    struct rusage ru; getrusage(RUSAGE_SELF,&ru);
    snprintf(path,sizeof(path),"%s/summary.tsv",outdir);
    FILE *sf=fopen(path,"wb"); if(!sf) die(path);
    fprintf(sf,"first\tcount\tvalid\tfailed\ttarget_leaf_0_written\twall_seconds\tuser_seconds\tmaxrss_kib\n");
    fprintf(sf,"%u\t%u\t%u\t%u\t%u\t%.6f\t%.6f\t%ld\n",first,count,count-failed,failed,target,
            now()-start,(double)ru.ru_utime.tv_sec+ru.ru_utime.tv_usec/1e6,ru.ru_maxrss);
    fclose(sf);
    printf("first=%u count=%u valid=%u failed=%u retained=%u wall=%.3f\n",
           first,count,count-failed,failed,target,now()-start);
    free(sig);
    return 0;
}
