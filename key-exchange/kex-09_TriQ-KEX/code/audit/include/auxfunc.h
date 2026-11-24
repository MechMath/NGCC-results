#ifndef AUDIT_AUXFUNC_H
#define AUDIT_AUXFUNC_H

int pseudoXOF(unsigned long long outlen_bits,
              const unsigned char *input,
              unsigned long long input_len_bits,
              unsigned char *out);

#endif
