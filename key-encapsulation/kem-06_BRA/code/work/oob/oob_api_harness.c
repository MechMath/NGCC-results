#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "drng.h"
#include "KEM_BRA-128.h"

DRNG_ctx drng_algorithm;

static void init_drng(void) {
  unsigned char nonce[64];
  memset(nonce, 0x42, sizeof(nonce));
  init_random_number(&drng_algorithm, nonce, sizeof(nonce));
}

static void *xcalloc(size_t count, size_t size) {
  void *p = calloc(count, size);
  if (p == NULL) {
    fprintf(stderr, "calloc(%zu, %zu) failed\n", count, size);
    exit(2);
  }
  return p;
}

static void run_positive(long declared_length) {
  unsigned long long pk_len = kem_get_pk_len_bytes();
  unsigned long long sk_len = kem_get_sk_len_bytes();
  unsigned long long ct_len = kem_get_ct_len_bytes();
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned long long out_ss_len = 0;
  unsigned char *pk = xcalloc(pk_len, 1);
  unsigned char *sk = xcalloc(sk_len, 1);
  unsigned char *ct = xcalloc(ct_len, 1);
  unsigned char *ss_enc = xcalloc(ss_len, 1);
  unsigned char *ss_dec = xcalloc(ss_len, 1);
  int keygen_rc;
  int enc_rc;
  int dec_rc;

  init_drng();
  keygen_rc = kem_keygen(pk, &pk_len, sk, &sk_len);
  if (keygen_rc != 0) {
    fprintf(stderr, "keygen failed: %d\n", keygen_rc);
    exit(3);
  }

  enc_rc = kem_enc(pk, (unsigned long long)declared_length,
                   ss_enc, &ss_len, ct, &ct_len);
  if (enc_rc != 0) {
    fprintf(stderr, "enc failed: %d\n", enc_rc);
    exit(4);
  }

  dec_rc = kem_dec(sk, (unsigned long long)declared_length,
                   ct, (unsigned long long)declared_length,
                   ss_dec, &out_ss_len);
  printf("mode=positive declared_length=%ld keygen=%d enc=%d dec=%d "
         "pk_len=%llu sk_len=%llu ct_len=%llu ss_in=%llu ss_out=%llu "
         "shared_secret_equal=%d\n",
         declared_length, keygen_rc, enc_rc, dec_rc,
         kem_get_pk_len_bytes(), kem_get_sk_len_bytes(),
         kem_get_ct_len_bytes(), ss_len, out_ss_len,
         memcmp(ss_enc, ss_dec, ss_len) == 0);

  free(pk);
  free(sk);
  free(ct);
  free(ss_enc);
  free(ss_dec);
}

static void generate_material(unsigned char **pk_out,
                              unsigned char **sk_out,
                              unsigned char **ct_out,
                              unsigned long long *pk_len_out,
                              unsigned long long *sk_len_out,
                              unsigned long long *ct_len_out) {
  unsigned long long pk_len = kem_get_pk_len_bytes();
  unsigned long long sk_len = kem_get_sk_len_bytes();
  unsigned long long ct_len = kem_get_ct_len_bytes();
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned long long out_ss_len = 0;
  unsigned char *pk = xcalloc(pk_len, 1);
  unsigned char *sk = xcalloc(sk_len, 1);
  unsigned char *ct = xcalloc(ct_len, 1);
  unsigned char *ss = xcalloc(ss_len, 1);

  init_drng();
  if (kem_keygen(pk, &pk_len, sk, &sk_len) != 0 ||
      kem_enc(pk, pk_len, ss, &ss_len, ct, &ct_len) != 0 ||
      kem_dec(sk, sk_len, ct, ct_len, ss, &out_ss_len) != 0) {
    fprintf(stderr, "material generation failed\n");
    exit(5);
  }

  free(ss);
  *pk_out = pk;
  *sk_out = sk;
  *ct_out = ct;
  *pk_len_out = pk_len;
  *sk_len_out = sk_len;
  *ct_len_out = ct_len;
}

static void run_short_input(const char *mode) {
  unsigned char *pk = NULL;
  unsigned char *sk = NULL;
  unsigned char *ct = NULL;
  unsigned long long pk_len = 0;
  unsigned long long sk_len = 0;
  unsigned long long ct_len = 0;
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned char *ss = xcalloc(ss_len, 1);
  unsigned char *short_input = xcalloc(1, 1);
  int rc;

  short_input[0] = 0;
  generate_material(&pk, &sk, &ct, &pk_len, &sk_len, &ct_len);

  fprintf(stderr,
          "about_to_call mode=%s actual_input_capacity=1 "
          "declared_input_length=1 canonical_pk=%llu canonical_sk=%llu "
          "canonical_ct=%llu\n",
          mode, pk_len, sk_len, ct_len);
  fflush(stderr);

  if (strcmp(mode, "enc_short_pk") == 0) {
    rc = kem_enc(short_input, 1, ss, &ss_len, ct, &ct_len);
  } else if (strcmp(mode, "dec_short_sk") == 0) {
    rc = kem_dec(short_input, 1, ct, ct_len, ss, &ss_len);
  } else if (strcmp(mode, "dec_short_ct") == 0) {
    rc = kem_dec(sk, sk_len, short_input, 1, ss, &ss_len);
  } else {
    fprintf(stderr, "unknown mode: %s\n", mode);
    exit(6);
  }

  fprintf(stderr, "call_returned mode=%s rc=%d\n", mode, rc);
  free(pk);
  free(sk);
  free(ct);
  free(ss);
  free(short_input);
}

__attribute__((noinline))
static int call_with_one_byte_stack_input(const char *mode,
                                          unsigned char *sk,
                                          unsigned long long sk_len,
                                          unsigned char *ct,
                                          unsigned long long ct_len,
                                          unsigned char *ss,
                                          unsigned long long *ss_len) {
  volatile unsigned char one_byte_input[1] = {0};
  unsigned char *p = (unsigned char *)one_byte_input;

  if (strcmp(mode, "enc_short_pk_stack") == 0) {
    return kem_enc(p, 1, ss, ss_len, ct, &ct_len);
  }
  if (strcmp(mode, "dec_short_sk_stack") == 0) {
    return kem_dec(p, 1, ct, ct_len, ss, ss_len);
  }
  if (strcmp(mode, "dec_short_ct_stack") == 0) {
    return kem_dec(sk, sk_len, p, 1, ss, ss_len);
  }
  return -999;
}

static void run_short_stack_input(const char *mode) {
  unsigned char *pk = NULL;
  unsigned char *sk = NULL;
  unsigned char *ct = NULL;
  unsigned long long pk_len = 0;
  unsigned long long sk_len = 0;
  unsigned long long ct_len = 0;
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned char *ss = xcalloc(ss_len, 1);
  int rc;

  generate_material(&pk, &sk, &ct, &pk_len, &sk_len, &ct_len);
  fprintf(stderr,
          "about_to_call mode=%s actual_input_capacity=1 "
          "declared_input_length=1 storage=stack canonical_pk=%llu "
          "canonical_sk=%llu canonical_ct=%llu\n",
          mode, pk_len, sk_len, ct_len);
  fflush(stderr);
  rc = call_with_one_byte_stack_input(mode, sk, sk_len, ct, ct_len,
                                      ss, &ss_len);
  fprintf(stderr, "call_returned mode=%s rc=%d\n", mode, rc);
  free(pk);
  free(sk);
  free(ct);
  free(ss);
}

static void run_guard_input(const char *mode) {
  unsigned char *pk = NULL;
  unsigned char *sk = NULL;
  unsigned char *ct = NULL;
  unsigned long long pk_len = 0;
  unsigned long long sk_len = 0;
  unsigned long long ct_len = 0;
  unsigned long long ss_len = kem_get_ss_len_bytes();
  unsigned char *ss = xcalloc(ss_len, 1);
  long page_size = sysconf(_SC_PAGESIZE);
  unsigned char *mapping = NULL;
  unsigned char *one_byte_input = NULL;
  int rc;

  if (page_size <= 0) {
    fprintf(stderr, "invalid page size\n");
    exit(7);
  }
  mapping = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED ||
      mprotect(mapping + page_size, (size_t)page_size, PROT_NONE) != 0) {
    perror("guard allocation");
    exit(8);
  }
  one_byte_input = mapping + page_size - 1;
  *one_byte_input = 0;

  generate_material(&pk, &sk, &ct, &pk_len, &sk_len, &ct_len);
  fprintf(stderr,
          "about_to_call mode=%s actual_input_capacity=1 "
          "declared_input_length=1 storage=guard_page canonical_pk=%llu "
          "canonical_sk=%llu canonical_ct=%llu\n",
          mode, pk_len, sk_len, ct_len);
  fflush(stderr);

  if (strcmp(mode, "enc_short_pk_guard") == 0) {
    rc = kem_enc(one_byte_input, 1, ss, &ss_len, ct, &ct_len);
  } else if (strcmp(mode, "dec_short_sk_guard") == 0) {
    rc = kem_dec(one_byte_input, 1, ct, ct_len, ss, &ss_len);
  } else if (strcmp(mode, "dec_short_ct_guard") == 0) {
    rc = kem_dec(sk, sk_len, one_byte_input, 1, ss, &ss_len);
  } else {
    fprintf(stderr, "unknown guard mode: %s\n", mode);
    exit(9);
  }

  fprintf(stderr, "call_returned mode=%s rc=%d\n", mode, rc);
  free(pk);
  free(sk);
  free(ct);
  free(ss);
  munmap(mapping, (size_t)page_size * 2);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr,
            "usage: %s positive|positive-ignored-length|enc_short_pk|"
            "dec_short_sk|dec_short_ct|enc_short_pk_stack|"
            "dec_short_sk_stack|dec_short_ct_stack|enc_short_pk_guard|"
            "dec_short_sk_guard|dec_short_ct_guard\n",
            argv[0]);
    return 2;
  }

  if (strcmp(argv[1], "positive") == 0) {
    run_positive((long)kem_get_pk_len_bytes());
  } else if (strcmp(argv[1], "positive-ignored-length") == 0) {
    run_positive(1);
  } else if (strstr(argv[1], "_guard") != NULL) {
    run_guard_input(argv[1]);
  } else if (strstr(argv[1], "_stack") != NULL) {
    run_short_stack_input(argv[1]);
  } else {
    run_short_input(argv[1]);
  }
  return 0;
}
