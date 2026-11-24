#ifndef AUDIT_KEX_ALGORITHM_INSTANCE_H
#define AUDIT_KEX_ALGORITHM_INSTANCE_H

unsigned long long kex_get_passes_num(void);
unsigned long long kex_get_pk_len_bytes(void);
unsigned long long kex_get_sk_len_bytes(void);
unsigned long long kex_get_sta_len_bytes(void);
unsigned long long kex_get_stb_len_bytes(void);
unsigned long long kex_get_ss_len_bytes(void);
unsigned long long kex_get_total_msg_len_bytes(void);

int kex_init_a(unsigned char *, unsigned long long *, unsigned char *,
               unsigned long long *, unsigned char *, unsigned long long *);
int kex_init_b(unsigned char *, unsigned long long *, unsigned char *,
               unsigned long long *, unsigned char *, unsigned long long *);
int kex_generate_pass1_msg_a(unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long *,
                             unsigned char *, unsigned long long *);
int kex_generate_pass2_msg_b(unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long *,
                             unsigned char *, unsigned long long *);
int kex_generate_pass3_msg_a(unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long,
                             unsigned char *, unsigned long long *,
                             unsigned char *, unsigned long long *);
int kex_derive_ss_a(unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long *);
int kex_derive_ss_b(unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long,
                    unsigned char *, unsigned long long *);

#endif
