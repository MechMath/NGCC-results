#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "KEM_AlgorithmInstance.h"
#include "owcpa.h"
#include "verify.h"

static uint64_t fnv1a64(const uint8_t *p, size_t n)
{
  uint64_t h = UINT64_C(0xcbf29ce484222325);
  size_t i;

  for (i = 0; i < n; i++) {
    h ^= p[i];
    h *= UINT64_C(0x100000001b3);
  }
  return h;
}

static void fill_pattern(uint8_t *p, size_t n, uint8_t seed)
{
  size_t i;

  for (i = 0; i < n; i++) {
    p[i] = (uint8_t)(seed + 37u * i + (i >> 3));
  }
}

static void print_hash(const char *label, const uint8_t *p, size_t n)
{
  printf("%s_len=%zu %s_fnv1a64=%016" PRIx64 "\n", label, n, label,
         fnv1a64(p, n));
}

static void *xmalloc(size_t n)
{
  void *p = malloc(n);

  if (p == NULL) {
    fprintf(stderr, "malloc(%zu) failed: %s\n", n, strerror(errno));
    exit(90);
  }
  return p;
}

static int run_deterministic(unsigned repetitions)
{
  uint8_t *pk = xmalloc(KEM_PUBLICKEYBYTES);
  uint8_t *sk = xmalloc(KEM_SECRETKEYBYTES);
  uint8_t *rnd = xmalloc(SEED_BYTES);
  uint8_t *ss = xmalloc(KEM_BYTES);
  uint8_t *ct = xmalloc(KEM_CIPHERTEXTBYTES);
  uint64_t first_ss = 0, first_ct = 0;
  unsigned i;
  int rc;

  fill_pattern(rnd, SEED_BYTES, 0x5a);
  memset(pk, 0xa5, KEM_PUBLICKEYBYTES);
  memset(sk, 0x5a, KEM_SECRETKEYBYTES);
  memset(ss, 0xa5, KEM_BYTES);
  memset(ct, 0xa5, KEM_CIPHERTEXTBYTES);

  printf("case=mdkem_enc params=%d seed_bytes=%u pk_bytes=%zu sk_bytes=%zu "
         "ct_bytes=%zu reps=%u rnd_pattern=seed=0x5a\n",
         PARAMS, (unsigned)SEED_BYTES, (size_t)KEM_PUBLICKEYBYTES,
         (size_t)KEM_SECRETKEYBYTES, (size_t)KEM_CIPHERTEXTBYTES,
         repetitions);
  print_hash("rnd", rnd, SEED_BYTES);

  rc = mkem_keygen(pk, sk);
  printf("keygen_return=%d\n", rc);
  print_hash("pk", pk, KEM_PUBLICKEYBYTES);

  for (i = 0; i < repetitions; i++) {
    memset(ss, 0xa5, KEM_BYTES);
    memset(ct, 0xa5, KEM_CIPHERTEXTBYTES);
    printf("call=%u begin\n", i);
    fflush(stdout);
    rc = mdkem_enc(pk, rnd, ss, ct);
    printf("call=%u return=%d\n", i, rc);
    if (i == 0) {
      first_ss = fnv1a64(ss, KEM_BYTES);
      first_ct = fnv1a64(ct, KEM_CIPHERTEXTBYTES);
    }
    printf("call=%u ss_repeat=%d ct_repeat=%d\n", i,
           fnv1a64(ss, KEM_BYTES) == first_ss,
           fnv1a64(ct, KEM_CIPHERTEXTBYTES) == first_ct);
    print_hash("ss", ss, KEM_BYTES);
    print_hash("ct", ct, KEM_CIPHERTEXTBYTES);
  }

  free(ct);
  free(ss);
  free(rnd);
  free(sk);
  free(pk);
  return 0;
}

static int run_standard_controls(void)
{
  uint8_t *pk = xmalloc(KEM_PUBLICKEYBYTES);
  uint8_t *sk = xmalloc(KEM_SECRETKEYBYTES);
  uint8_t *ss_enc = xmalloc(KEM_BYTES);
  uint8_t *ss_dec = xmalloc(KEM_BYTES);
  uint8_t *ss_bad1 = xmalloc(KEM_BYTES);
  uint8_t *ss_bad2 = xmalloc(KEM_BYTES);
  uint8_t *ct = xmalloc(KEM_CIPHERTEXTBYTES);
  uint8_t *msg = xmalloc(SEED_BYTES);
  uint8_t *buf = xmalloc(3 * SEED_BYTES);
  uint8_t *kr = xmalloc(2 * SEED_BYTES);
  uint8_t *cmp = xmalloc(KEM_CIPHERTEXTBYTES + 10);
  uint8_t *expected_reject = xmalloc(KEM_BYTES);
  uint8_t *kdf_input = xmalloc(SEED_BYTES + KEM_CIPHERTEXTBYTES);
  const uint8_t *pk_in_sk = sk + POLYVEC_BYTES;
  const uint8_t *z = sk + KEM_SECRETKEYBYTES - SEED_BYTES;
  int internal_fail;
  size_t i;
  int rc;
  unsigned long long pk_len = KEM_PUBLICKEYBYTES;
  unsigned long long sk_len = KEM_SECRETKEYBYTES;
  unsigned long long ss_len = KEM_BYTES;
  unsigned long long ct_len = KEM_CIPHERTEXTBYTES;

  printf("case=standard_controls params=%d seed_bytes=%u pk_bytes=%zu "
         "sk_bytes=%zu ct_bytes=%zu\n",
         PARAMS, (unsigned)SEED_BYTES, (size_t)KEM_PUBLICKEYBYTES,
         (size_t)KEM_SECRETKEYBYTES, (size_t)KEM_CIPHERTEXTBYTES);

  rc = kem_keygen(pk, &pk_len, sk, &sk_len);
  printf("keygen_return=%d\n", rc);
  rc = kem_enc(pk, pk_len, ss_enc, &ss_len, ct, &ct_len);
  printf("enc_return=%d\n", rc);
  print_hash("pk", pk, KEM_PUBLICKEYBYTES);
  print_hash("ct", ct, KEM_CIPHERTEXTBYTES);
  print_hash("ss_enc", ss_enc, KEM_BYTES);

  memset(ss_dec, 0, KEM_BYTES);
  rc = kem_dec(sk, sk_len, ct, ct_len, ss_dec, &ss_len);
  printf("valid_dec_return=%d valid_ss_equal=%d\n", rc,
         memcmp(ss_enc, ss_dec, KEM_BYTES) == 0);
  print_hash("ss_dec_valid", ss_dec, KEM_BYTES);

  ct[KEM_CIPHERTEXTBYTES - 1] ^= 1;
  print_hash("ct_tampered", ct, KEM_CIPHERTEXTBYTES);

  /* Recompute exactly the reference mkem_dec re-encryption comparison. */
  owcpa_dec(msg, ct, sk);
  memcpy(buf, msg, SEED_BYTES);
  for (i = 0; i < SEED_BYTES; i++) {
    buf[SEED_BYTES + i] = sk[KEM_SECRETKEYBYTES - 2 * SEED_BYTES + i];
  }
  Hash2(kr, buf, 2 * SEED_BYTES);
  owcpa_enc(cmp, buf, pk_in_sk, kr + SEED_BYTES);
  internal_fail = verify(ct, cmp, KEM_CIPHERTEXTBYTES);
  printf("internal_reencryption_fail=%d\n", internal_fail);
  print_hash("reference_cmp", cmp, KEM_CIPHERTEXTBYTES);

  /* Compute the intended implicit-rejection output z||ct under the KDF macro. */
  memcpy(kdf_input, z, SEED_BYTES);
  memcpy(kdf_input + SEED_BYTES, ct, KEM_CIPHERTEXTBYTES);
  KDF(expected_reject, KEM_BYTES, kdf_input,
      SEED_BYTES + KEM_CIPHERTEXTBYTES);

  memset(ss_bad1, 0, KEM_BYTES);
  rc = kem_dec(sk, sk_len, ct, ct_len, ss_bad1, &ss_len);
  printf("tampered_dec_1_return=%d\n", rc);
  print_hash("ss_bad_1", ss_bad1, KEM_BYTES);

  memset(ss_bad2, 0, KEM_BYTES);
  rc = kem_dec(sk, sk_len, ct, ct_len, ss_bad2, &ss_len);
  printf("tampered_dec_2_return=%d tampered_repeat=%d\n", rc,
         memcmp(ss_bad1, ss_bad2, KEM_BYTES) == 0);
  print_hash("ss_bad_2", ss_bad2, KEM_BYTES);
  printf("tampered_ss_equals_original=%d\n",
         memcmp(ss_bad1, ss_enc, KEM_BYTES) == 0);
  printf("tampered_ss_equals_intended_reject=%d\n",
         memcmp(ss_bad1, expected_reject, KEM_BYTES) == 0);
  print_hash("intended_reject", expected_reject, KEM_BYTES);

  free(kdf_input);
  free(expected_reject);
  free(cmp);
  free(kr);
  free(buf);
  free(msg);
  free(ct);
  free(ss_bad2);
  free(ss_bad1);
  free(ss_dec);
  free(ss_enc);
  free(sk);
  free(pk);
  return 0;
}

static int run_cca_trials(unsigned trials)
{
  uint8_t *pk = xmalloc(KEM_PUBLICKEYBYTES);
  uint8_t *sk = xmalloc(KEM_SECRETKEYBYTES);
  uint8_t *ss_enc = xmalloc(KEM_BYTES);
  uint8_t *ss_dec = xmalloc(KEM_BYTES);
  uint8_t *ss_bad = xmalloc(KEM_BYTES);
  uint8_t *ct = xmalloc(KEM_CIPHERTEXTBYTES);
  uint8_t *original_ct = xmalloc(KEM_CIPHERTEXTBYTES);
  uint8_t *msg = xmalloc(SEED_BYTES);
  uint8_t *buf = xmalloc(3 * SEED_BYTES);
  uint8_t *kr = xmalloc(2 * SEED_BYTES);
  uint8_t *cmp = xmalloc(KEM_CIPHERTEXTBYTES + 10);
  unsigned valid_ok = 0, changed = 0, failed = 0, same_ss = 0;
  unsigned cmp_original = 0, dec_return_zero = 0;
  unsigned trial;
  unsigned long long pk_len = KEM_PUBLICKEYBYTES;
  unsigned long long sk_len = KEM_SECRETKEYBYTES;
  unsigned long long ss_len = KEM_BYTES;
  unsigned long long ct_len = KEM_CIPHERTEXTBYTES;

  printf("case=cca_trials params=%d seed_bytes=%u trials=%u "
         "tamper=flip-low-bit-of-final-ciphertext-byte\n",
         PARAMS, (unsigned)SEED_BYTES, trials);

  for (trial = 0; trial < trials; trial++) {
    const uint8_t *pk_in_sk;
    size_t i;

    kem_keygen(pk, &pk_len, sk, &sk_len);
    kem_enc(pk, pk_len, ss_enc, &ss_len, ct, &ct_len);
    memcpy(original_ct, ct, KEM_CIPHERTEXTBYTES);
    kem_dec(sk, sk_len, ct, ct_len, ss_dec, &ss_len);
    if (memcmp(ss_enc, ss_dec, KEM_BYTES) == 0) {
      valid_ok++;
    }

    ct[KEM_CIPHERTEXTBYTES - 1] ^= 1;
    if (memcmp(ct, original_ct, KEM_CIPHERTEXTBYTES) != 0) {
      changed++;
    }

    owcpa_dec(msg, ct, sk);
    memcpy(buf, msg, SEED_BYTES);
    for (i = 0; i < SEED_BYTES; i++) {
      buf[SEED_BYTES + i] =
          sk[KEM_SECRETKEYBYTES - 2 * SEED_BYTES + i];
    }
    Hash2(kr, buf, 2 * SEED_BYTES);
    pk_in_sk = sk + POLYVEC_BYTES;
    owcpa_enc(cmp, buf, pk_in_sk, kr + SEED_BYTES);
    if (verify(ct, cmp, KEM_CIPHERTEXTBYTES) != 0) {
      failed++;
    }
    if (memcmp(cmp, original_ct, KEM_CIPHERTEXTBYTES) == 0) {
      cmp_original++;
    }

    if (kem_dec(sk, sk_len, ct, ct_len, ss_bad, &ss_len) == 0) {
      dec_return_zero++;
    }
    if (memcmp(ss_bad, ss_enc, KEM_BYTES) == 0) {
      same_ss++;
    }
  }

  printf("valid_ok=%u/%u\n", valid_ok, trials);
  printf("ciphertext_changed=%u/%u\n", changed, trials);
  printf("internal_reencryption_fail=%u/%u\n", failed, trials);
  printf("reencryption_matches_original_ciphertext=%u/%u\n",
         cmp_original, trials);
  printf("tampered_decapsulation_return_zero=%u/%u\n",
         dec_return_zero, trials);
  printf("tampered_ss_equals_original=%u/%u\n", same_ss, trials);
  printf("single_query_cca_win_rate=%u/%u\n", same_ss, trials);

  free(cmp);
  free(kr);
  free(buf);
  free(msg);
  free(original_ct);
  free(ct);
  free(ss_bad);
  free(ss_dec);
  free(ss_enc);
  free(sk);
  free(pk);
  return (same_ss == trials) ? 0 : 1;
}

int main(int argc, char **argv)
{
  unsigned reps = 3;

  if (argc < 2) {
    fprintf(stderr, "usage: %s standard|mdkem|cca [reps]\n", argv[0]);
    return 64;
  }
  if (argc >= 3) {
    reps = (unsigned)strtoul(argv[2], NULL, 10);
  }

  if (strcmp(argv[1], "standard") == 0) {
    return run_standard_controls();
  }
  if (strcmp(argv[1], "mdkem") == 0) {
    return run_deterministic(reps);
  }
  if (strcmp(argv[1], "cca") == 0) {
    return run_cca_trials(reps);
  }
  fprintf(stderr, "unknown mode: %s\n", argv[1]);
  return 64;
}
