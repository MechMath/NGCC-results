#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

#include "api.h"
#include "auxfunc.h"
#include "counters.h"
#include "hash.h"
#include "utils.h"

#define BLOCK ((SPX_FORS_HEIGHT + 1) * SPX_N)
#define FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define FORS_OFF (SPX_N + COUNTER_SIZE)
#define SUFFIX_OFF (FORS_OFF + FORS_BYTES)
#define SUFFIX_BYTES (CRYPTO_BYTES - SUFFIX_OFF)
#define MAX_SEARCH 1000000000ULL

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return t.tv_sec+t.tv_nsec/1e9; }
static void die(const char *s) { fprintf(stderr,"fatal: %s: %s\n",s,strerror(errno)); exit(2); }
static void indices_of(unsigned *x,const unsigned char *d) {
    unsigned offset=0;
    for(unsigned i=0;i<SPX_FORS_TREES;i++){x[i]=0;for(unsigned j=0;j<SPX_FORS_HEIGHT;j++){x[i]^=((d[offset>>3]>>(offset&7))&1U)<<j;offset++;}}
}
static int digest_of(unsigned char *d,uint64_t *tree,uint32_t *leaf,const unsigned char *R,
                     const unsigned char *pk,const unsigned char *m,size_t ml,const spx_ctx *ctx,uint32_t c) {
    return hash_message(d,tree,leaf,R,pk,m,ml,ctx,&c);
}
static void write_file(const char *path,const void *p,size_t n){FILE*f=fopen(path,"wb");if(!f)die(path);if(n&&fwrite(p,1,n,f)!=n)die("write");if(fclose(f))die("close");}

int main(int argc,char **argv){
    if(argc!=2){fprintf(stderr,"usage: %s RECORD_MANIFEST\n",argv[0]);return 2;}
    double start=now();
    FILE *mf=fopen(argv[1],"rb"); if(!mf)die(argv[1]);
    unsigned char *fors=calloc((size_t)SPX_FORS_TREES*256*BLOCK,1);
    unsigned char *covered=calloc((size_t)SPX_FORS_TREES*256,1);
    unsigned *counts=calloc(SPX_FORS_TREES,sizeof(unsigned));
    if(!fors||!covered||!counts)die("coverage");
    unsigned char suffix[SUFFIX_BYTES],pk[CRYPTO_PUBLICKEYBYTES];
    int have_suffix=0,have_pk=0;
    unsigned char *sig=malloc(CRYPTO_BYTES); if(!sig)die("sig");
    char path[4096];
    FILE *rlog=fopen("experiments/retained-records.tsv","wb");
    FILE *clog=fopen("experiments/fors-coverage.tsv","wb");
    if(!rlog||!clog)die("log");
    fprintf(rlog,"retained_record\tquery\tmessage\teffective_leaf\n");
    fprintf(clog,"tree\tselected_index\tmessage\n");
    unsigned records=0;
    while(fgets(path,sizeof(path),mf)){
        path[strcspn(path,"\r\n")]=0;
        const char *base=strrchr(path,'/'); base=base?base+1:path;
        unsigned q=0; if(sscanf(base,"record-%6u.bin",&q)!=1){fprintf(stderr,"bad record path %s\n",path);return 2;}
        char msg[128]; int n=snprintf(msg,sizeof(msg),"ordinary-query-256f-%06u",q);
        FILE *rf=fopen(path,"rb"); if(!rf)die(path);
        if(fread(sig,1,CRYPTO_BYTES,rf)!=CRYPTO_BYTES)die("short record"); fclose(rf);
        char ppath[4096]; strncpy(ppath,path,sizeof(ppath)); ppath[sizeof(ppath)-1]=0;
        char *slash=strrchr(ppath,'/'); if(slash){strcpy(slash+1,"public-key.bin");}
        FILE *pf=fopen(ppath,"rb"); if(!pf)die(ppath);
        unsigned char pk2[CRYPTO_PUBLICKEYBYTES]; if(fread(pk2,1,sizeof(pk2),pf)!=sizeof(pk2))die("pk"); fclose(pf);
        if(!have_pk){memcpy(pk,pk2,sizeof(pk));have_pk=1;} else if(memcmp(pk,pk2,sizeof(pk))){fprintf(stderr,"public key mismatch\n");return 3;}
        spx_ctx ctx; memset(&ctx,0,sizeof(ctx));memcpy(ctx.pub_seed,pk,SPX_N);initialize_hash_function(&ctx);
        uint32_t c=get_fors_counter(sig); unsigned char d[SPX_FORS_MSG_BYTES];uint64_t tree;uint32_t leaf;
        if(digest_of(d,&tree,&leaf,sig,pk,(unsigned char*)msg,n,&ctx,c)){fprintf(stderr,"record prune failure\n");return 4;}
        if(tree||leaf){fprintf(stderr,"record wrong instance\n");return 4;}
        unsigned x[SPX_FORS_TREES]; indices_of(x,d);
        for(unsigned i=0;i<SPX_FORS_TREES;i++){
            size_t pos=(size_t)i*256+x[i];
            if(!covered[pos]){memcpy(fors+pos*BLOCK,sig+FORS_OFF+(size_t)i*BLOCK,BLOCK);covered[pos]=1;counts[i]++;fprintf(clog,"%u\t%u\t%s\n",i,x[i],msg);}
        }
        if(!have_suffix){memcpy(suffix,sig+SUFFIX_OFF,SUFFIX_BYTES);have_suffix=1;}
        fprintf(rlog,"%u\t%u\t%s\t0\n",records,q,msg);
        records++;
    }
    fclose(mf);fclose(rlog);fclose(clog);
    if(!have_pk||!have_suffix||!records){fprintf(stderr,"empty record set\n");return 5;}
    double coverage=1;for(unsigned i=0;i<SPX_FORS_TREES;i++)coverage*=counts[i]/256.0;
    const char *fresh="256f-fresh-unqueried-message-20261113";size_t flen=strlen(fresh);
    /* Message namespace makes absence structural; retained logs independently verify no collision. */
    spx_ctx ctx; memset(&ctx,0,sizeof(ctx));memcpy(ctx.pub_seed,pk,SPX_N);initialize_hash_function(&ctx);
    unsigned char *cand=malloc(CRYPTO_BYTES);if(!cand)die("candidate");
    uint64_t searched=0,pruned=0,wrong=0,uncovered=0;uint32_t win_counter=0;unsigned win_x[SPX_FORS_TREES];unsigned char win_R[SPX_N];
    double search_start=now();int found=0;
    while(searched<MAX_SEARCH){
        uint64_t variant=searched>>10;uint32_t c=(uint32_t)(searched&1023)+1;unsigned char sb[16];
        for(unsigned i=0;i<8;i++)sb[i]=(unsigned char)(variant>>(8*i));
        for(unsigned i=8;i<16;i++)sb[i]=(unsigned char)(0xa5u^(i*29u));
        unsigned char R[SPX_N];if(pseudoXOF((unsigned long long)SPX_N*8,sb,sizeof(sb)*8,R))return 2;
        unsigned char d[SPX_FORS_MSG_BYTES];uint64_t tree;uint32_t leaf;
        int h=digest_of(d,&tree,&leaf,R,pk,(const unsigned char*)fresh,flen,&ctx,c);searched++;
        if(h){pruned++;continue;}if(leaf){wrong++;continue;}
        unsigned x[SPX_FORS_TREES];indices_of(x,d);int all=1;
        for(unsigned i=0;i<SPX_FORS_TREES;i++)if(!covered[(size_t)i*256+x[i]]){all=0;break;}
        if(!all){uncovered++;continue;}
        memcpy(win_R,R,SPX_N);memcpy(win_x,x,sizeof(x));win_counter=c;found=1;break;
    }
    double search_time=now()-search_start;
    if(!found)return 6;
    memcpy(cand,win_R,SPX_N);ull_to_bytes(cand+SPX_N,COUNTER_SIZE,win_counter);
    for(unsigned i=0;i<SPX_FORS_TREES;i++){size_t p=(size_t)i*256+win_x[i];memcpy(cand+FORS_OFF+(size_t)i*BLOCK,fors+p*BLOCK,BLOCK);}
    memcpy(cand+SUFFIX_OFF,suffix,SUFFIX_BYTES);
    int rc=crypto_sign_verify(cand,CRYPTO_BYTES,(const unsigned char*)fresh,flen,pk);
    unsigned char sm[CRYPTO_BYTES];memcpy(sm,cand,CRYPTO_BYTES);sm[FORS_OFF+17]^=1;
    int smrc=crypto_sign_verify(sm,CRYPTO_BYTES,(const unsigned char*)fresh,flen,pk);
    unsigned char mm[256];memcpy(mm,fresh,flen);mm[0]^=1;
    int mmrc=crypto_sign_verify(cand,CRYPTO_BYTES,mm,flen,pk);
    write_file("experiments/public-key.bin",pk,sizeof(pk));write_file("experiments/forged-message.bin",fresh,flen);write_file("experiments/forged-signature.bin",cand,CRYPTO_BYTES);
    struct rusage ru;getrusage(RUSAGE_SELF,&ru);
    FILE *sf=fopen("experiments/forge-summary.tsv","wb");if(!sf)die("summary");
    fprintf(sf,"records\tpublic_key_bytes\tsignature_bytes\tcoverage_product\tsearched\tpruned\twrong_leaf\tuncovered\twinning_counter\tforged_rc\tsignature_mutation_rc\tmessage_mutation_rc\tdigest_search_seconds\twall_seconds\tuser_seconds\tmaxrss_kib\n");
    fprintf(sf,"%u\t%d\t%d\t%.17g\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu64"\t%"PRIu32"\t%d\t%d\t%d\t%.6f\t%.6f\t%.6f\t%ld\n",
        records,CRYPTO_PUBLICKEYBYTES,CRYPTO_BYTES,coverage,searched,pruned,wrong,uncovered,win_counter,rc,smrc,mmrc,
        search_time,now()-start,(double)ru.ru_utime.tv_sec+ru.ru_utime.tv_usec/1e6,ru.ru_maxrss);
    for(unsigned i=0;i<SPX_FORS_TREES;i++)fprintf(sf,"coverage_%u\t%u/256\n",i,counts[i]);
    for(unsigned i=0;i<SPX_FORS_TREES;i++)fprintf(sf,"index_%u\t%u\n",i,win_x[i]);
    fclose(sf);
    printf("records=%u coverage=%.12g searched=%"PRIu64" win_counter=%"PRIu32" forged_rc=%d sig_mut_rc=%d msg_mut_rc=%d\n",records,coverage,searched,win_counter,rc,smrc,mmrc);
    return rc==0&&smrc!=0&&mmrc!=0?0:7;
}
