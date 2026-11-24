#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "drng.h"
#include "sign.h"

#define SEED_LEN 64
#define MAX_M 1024
#define MAX_CTX 255

DRNG_ctx drng_algorithm;

static uint64_t digest = UINT64_C(1469598103934665603);

static void eat(const void *vp, size_t n) {
  const uint8_t *p = (const uint8_t *)vp;
  while (n--) {
    digest ^= *p++;
    digest *= UINT64_C(1099511628211);
  }
}

static void eat_u64(uint64_t x) { eat(&x, sizeof(x)); }

static void fill(DRNG_ctx *r, uint8_t *p, size_t n) {
  if (n) get_random_number(r, p, n * 8ULL);
}

int main(int argc, char **argv) {
  static const size_t mlens[] = {0, 1, 2, 3, 31, 32, 55, 59, 63, 64, 255, 1024};
  static const size_t ctxlens[] = {0, 1, 2, 31, 32, 127, 254, 255};
  uint64_t count = argc > 1 ? strtoull(argv[1], NULL, 10) : 1000;
  DRNG_ctx rseed, rmsg, rctx;
  uint8_t nonce[SEED_LEN];
  uint64_t valid_ok = 0, msg_rej = 0, ctx_rej = 0;
  uint64_t mut_total = 0, mut_rej = 0, overlong_ok = 0;
  uint64_t accepted_first = UINT64_MAX;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint8_t m[MAX_M], ctx[MAX_CTX], sig[CRYPTO_BYTES], tmp[CRYPTO_BYTES];

  for (size_t i = 0; i < sizeof(nonce); ++i) nonce[i] = (uint8_t)(i * 131u + 17u);
  init_random_number(&rseed, nonce, sizeof(nonce));
  nonce[0] ^= 0x5a; init_random_number(&rmsg, nonce, sizeof(nonce));
  nonce[0] ^= 0x3c; init_random_number(&rctx, nonce, sizeof(nonce));
  memset(m, 0, sizeof(m));
  memset(ctx, 0, sizeof(ctx));

  for (uint64_t i = 0; i < count; ++i) {
    size_t mlen = mlens[i % (sizeof(mlens) / sizeof(mlens[0]))];
    size_t ctxlen = ctxlens[(i / 3) % (sizeof(ctxlens) / sizeof(ctxlens[0]))];
    uint8_t seed[SEED_LEN], rnd[128];
    size_t siglen = 0;
    int ret;

    fill(&rseed, seed, sizeof(seed));
    fill(&rmsg, m, mlen);
    fill(&rctx, ctx, ctxlen);
    init_random_number(&drng_algorithm, seed, sizeof(seed));
    if (crypto_sign_keypair(pk, sk) != 0) return 2;
    if (crypto_sign_signature(sig, &siglen, m, mlen, ctx, ctxlen, sk) != 0 ||
        siglen != CRYPTO_BYTES) return 3;
    if (crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk) != 0) return 4;
    ++valid_ok;

    eat_u64(i); eat_u64(mlen); eat_u64(ctxlen); eat(pk, sizeof(pk));
    eat(m, mlen); eat(ctx, ctxlen); eat(sig, siglen);

    memcpy(tmp, sig, sizeof(sig));
    fill(&rmsg, rnd, sizeof(rnd));
    {
      size_t at = rnd[0] % (mlen ? mlen : ctxlen ? ctxlen : 1);
      uint8_t old;
      if (mlen) {
        old = m[at]; m[at] ^= (uint8_t)(1u << (rnd[1] & 7));
        ret = crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk);
        m[at] = old;
      } else if (ctxlen) {
        old = ctx[at]; ctx[at] ^= (uint8_t)(1u << (rnd[1] & 7));
        ret = crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk);
        ctx[at] = old;
      } else {
        ret = crypto_sign_verify(sig, siglen, m, 1, ctx, ctxlen, pk);
      }
      if (ret != 0) ++msg_rej;
    }

    if (ctxlen) {
      size_t at = rnd[2] % ctxlen;
      uint8_t old = ctx[at];
      ctx[at] ^= (uint8_t)(1u << (rnd[3] & 7));
      ret = crypto_sign_verify(sig, siglen, m, mlen, ctx, ctxlen, pk);
      ctx[at] = old;
      if (ret != 0) ++ctx_rej;
    }

    {
      size_t hint_off = CTILDEBYTES + L * POLYZ_PACKEDBYTES;
      size_t npos = 3 + (i % (POLYVECH_POSBYTES + K + 16));
      for (size_t q = 0; q < npos; ++q) {
        size_t off;
        if (q == 0) off = hint_off + (i % POLYVECH_POSBYTES);
        else if (q == 1) off = hint_off + POLYVECH_POSBYTES + ((i + 1) % K);
        else if (q == 2) off = hint_off + ((i * 37 + 11) % POLYVECH_POSBYTES);
        else off = CTILDEBYTES + ((i * 97 + q * 211) % (sizeof(sig) - CTILDEBYTES));
        memcpy(tmp, sig, sizeof(sig));
        tmp[off] ^= (uint8_t)(1u << ((i + q) & 7));
        ret = crypto_sign_verify(tmp, siglen, m, mlen, ctx, ctxlen, pk);
        ++mut_total;
        if (ret != 0) ++mut_rej;
        else if (accepted_first == UINT64_MAX) accepted_first = i;
      }
    }

    ret = crypto_sign_signature(tmp, &siglen, m, mlen, ctx, 256, sk);
    if (ret != 0) ++overlong_ok;
  }

  eat_u64(valid_ok); eat_u64(msg_rej); eat_u64(ctx_rej);
  eat_u64(mut_total); eat_u64(mut_rej); eat_u64(accepted_first);
  printf("level=%d cases=%llu digest=%016llx valid_ok=%llu message_or_empty_control_rejected=%llu context_rejected=%llu mutations=%llu mutations_rejected=%llu accepted_first=%lld overlong_ctx_rejected=%llu\n",
         CRYPTO_PUBLICKEYBYTES + (int)CRYPTO_BYTES,
         (unsigned long long)count, (unsigned long long)digest,
         (unsigned long long)valid_ok, (unsigned long long)msg_rej,
         (unsigned long long)ctx_rej, (unsigned long long)mut_total,
         (unsigned long long)mut_rej,
         accepted_first == UINT64_MAX ? -1LL : (long long)accepted_first,
         (unsigned long long)overlong_ok);
  return accepted_first == UINT64_MAX ? 0 : 5;
}
