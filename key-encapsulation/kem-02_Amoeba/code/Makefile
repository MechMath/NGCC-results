CC ?= gcc
ROOT := source_archive/Implementations/Reference_Implementation/Amoeba-576/src
INCLUDES := -I$(ROOT)/backend -I$(ROOT)/symmetric
DEFS := -DSECURITY_LEVEL=128
CFLAGS := -O2 -std=gnu11 -Dinline=static -w $(DEFS) $(INCLUDES)
SOURCES := comparator_experiment.c \
	$(ROOT)/backend/ccakem.c \
	$(ROOT)/backend/cpapke.c \
	$(ROOT)/backend/hamming.c \
	$(ROOT)/backend/ntt_2s3t.c \
	$(ROOT)/backend/poly.c \
	$(ROOT)/backend/randombytes.c \
	$(ROOT)/backend/zetas.c \
	$(ROOT)/symmetric/auxfunc.c \
	$(ROOT)/symmetric/drng.c

.PHONY: all run clean

all: comparator_experiment

comparator_experiment: $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

run: comparator_experiment
	./comparator_experiment

clean:
	rm -f comparator_experiment
