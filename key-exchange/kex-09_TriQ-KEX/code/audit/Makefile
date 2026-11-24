CC ?= gcc
CFLAGS ?= -std=c99 -O2 -g -Wall -Wextra -Werror -pedantic
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
CPPFLAGS = -Iinclude

.PHONY: all sanitize clean

all: out/kex_audit

out/kex_audit: KEX_AlgorithmInstance.c stubs.c harness.c
	mkdir -p out
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

sanitize: CFLAGS += $(SANFLAGS)
sanitize: out/kex_audit_san

out/kex_audit_san: KEX_AlgorithmInstance.c stubs.c harness.c
	mkdir -p out
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

clean:
	rm -f out/kex_audit out/kex_audit_san
