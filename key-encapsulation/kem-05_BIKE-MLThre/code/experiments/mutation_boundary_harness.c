#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "kem.h"
#include "sampling.h"
#include "sha.h"
#include "gf2x.h"
#include "FromNIST/rng.h"

#ifndef VARIANT
#define VARIANT "unknown"
#endif
enum { KEYS = 8, REPETITIONS = 24 };

static ret_t function_h(pad_e_t *e, const m_t *m)
{
    seed_t seed = {0};
    bike_memcpy(seed.raw, m->raw, sizeof(seed));
    return generate_error_vector(e, &seed);
}
static ret_t function_l(m_t *out, const pad_e_t *e)
{
    DEFER_CLEANUP(sha_dgst_t dgst = {0}, sha_dgst_cleanup);
    DEFER_CLEANUP(e_t tmp, e_cleanup);
    tmp.val[0] = e->val[0].val; tmp.val[1] = e->val[1].val;
    GUARD(sha(&dgst, sizeof(tmp), (uint8_t *)&tmp));
    bike_memcpy(out->raw, dgst.u.raw, sizeof(*out));
    return SUCCESS;
}
static ret_t function_k(ss_t *out, const m_t *m, const ct_t *ct)
{
    DEFER_CLEANUP(func_k_t tmp, func_k_cleanup);
    DEFER_CLEANUP(sha_dgst_t dgst, sha_dgst_cleanup);
    tmp.m=*m; tmp.c0=ct->c0; tmp.c1=ct->c1;
    GUARD(sha(&dgst, sizeof(tmp), (uint8_t *)&tmp));
    bike_memcpy(out->raw, dgst.u.raw, sizeof(*out));
    return SUCCESS;
}
static ret_t encrypt(ct_t *ct, const pad_e_t *e, const pk_t *pk, const m_t *m)
{
    pad_r_t c={0},p={0}; p.val=*pk;
    gf2x_mod_mul(&c,&e->val[1],&p);
    gf2x_mod_add(&c,&c,&e->val[0]);
    ct->c0=c.val; GUARD(function_l(&ct->c1,e));
    for(size_t i=0;i<sizeof(*m);i++) ct->c1.raw[i]^=m->raw[i];
    return SUCCESS;
}
static void init_drbg(uint32_t key)
{
    unsigned char seed[48];
    for(uint32_t i=0;i<sizeof(seed);i++) seed[i]=(unsigned char)(0xa7U^(i*11U)^key);
    randombytes_init(seed,NULL,256);
}
static uint64_t next64(uint32_t *s)
{
    uint64_t x=*s; x^=x<<13; x^=x>>7; x^=x<<17; *s=(uint32_t)x; return x;
}
static void mutate(r_t *c0, uint32_t bits, uint32_t seed)
{
    uint32_t s=seed;
    for(uint32_t n=0;n<bits;){
        uint32_t pos=(uint32_t)(next64(&s)%R_BITS);
        uint8_t mask=(uint8_t)(1U<<(pos%8));
        c0->raw[pos/8]^=mask; n++;
    }
}
static uint64_t hash_bytes(const unsigned char *x,size_t n)
{
    uint64_t h=UINT64_C(1469598103934665603);
    for(size_t i=0;i<n;i++){h^=x[i];h*=UINT64_C(1099511628211);} return h;
}
int main(void)
{
    static const unsigned bits[]={1,2,3,4,5,6,8,10,12,16,20,24,32};
    unsigned char *pk_raw=calloc(1,CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk_raw=calloc(1,CRYPTO_SECRETKEYBYTES);
    unsigned char *ct_raw=calloc(1,CRYPTO_CIPHERTEXTBYTES);
    unsigned char *ss=calloc(1,CRYPTO_BYTES), *native=calloc(1,CRYPTO_BYTES);
    if(!pk_raw||!sk_raw||!ct_raw||!ss||!native) return 2;
    puts("variant,key,control_match,bits,rep,ret,match,ct_fnv1a64,ss_fnv1a64");
    for(uint32_t key=0;key<KEYS;key++){
        init_drbg(key);
        if(crypto_kem_keypair(pk_raw,sk_raw)) return 3;
        int crc=crypto_kem_enc(ct_raw,native,pk_raw), drc=crypto_kem_dec(ss,ct_raw,sk_raw);
        printf("%s,%u,%d,control,0,0,0,0,0\n",VARIANT,key,
               crc==0&&drc==0&&!memcmp(ss,native,CRYPTO_BYTES));
        pk_t pk={0}; bike_memcpy(&pk,pk_raw,sizeof(pk));
        for(uint32_t rep=0;rep<REPETITIONS;rep++){
            DEFER_CLEANUP(m_t m,m_cleanup);
            DEFER_CLEANUP(pad_e_t e,pad_e_cleanup);
            DEFER_CLEANUP(ct_t ct,ct_cleanup);
            DEFER_CLEANUP(ss_t expected,ss_cleanup);
            randombytes(m.raw,sizeof(m.raw));
            if(function_h(&e,&m)!=SUCCESS) return 4;
            if(encrypt(&ct,&e,&pk,&m)!=SUCCESS) return 5;
            if(function_k(&expected,&m,&ct)!=SUCCESS) return 6;
            for(size_t bi=0;bi<sizeof(bits)/sizeof(bits[0]);bi++){
                ct_t mut=ct;
                uint32_t seed=UINT32_C(0x9e3779b9)^key^rep*UINT32_C(0x85ebca6b)^bits[bi];
                mutate(&mut.c0,bits[bi],seed);
                bike_memcpy(ct_raw,&mut,sizeof(mut));
                int rc=crypto_kem_dec(ss,ct_raw,sk_raw);
                int match=rc==0&&!memcmp(ss,expected.raw,CRYPTO_BYTES);
                printf("%s,%u,1,%u,%u,%d,%d,%016"PRIx64",%016"PRIx64"\n",
                       VARIANT,key,bits[bi],rep,rc,match,
                       hash_bytes(ct_raw,CRYPTO_CIPHERTEXTBYTES),hash_bytes(ss,CRYPTO_BYTES));
            }
        }
    }
    free(native);free(ss);free(ct_raw);free(sk_raw);free(pk_raw);return 0;
}
