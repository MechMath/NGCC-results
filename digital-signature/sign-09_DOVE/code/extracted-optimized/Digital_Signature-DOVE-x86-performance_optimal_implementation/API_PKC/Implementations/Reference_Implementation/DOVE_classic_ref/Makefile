CC = gcc
CFLAGS = -Wall -Wextra -O2

# 默认参数集 DOVE128，可通过 make DOVE_PARAM=256/512 切换
DOVE_PARAM = 128
ifeq ($(DOVE_PARAM),128)
CFLAGS += -DDOVE_PARAM_SET=DOVE128
endif
ifeq ($(DOVE_PARAM),256)
CFLAGS += -DDOVE_PARAM_SET=DOVE256
endif
ifeq ($(DOVE_PARAM),512)
CFLAGS += -DDOVE_PARAM_SET=DOVE512
endif

TARGET = dove_sign_kat
BENCH = bench_sign
OBJS = gf256.o matrix.o uov/blas_matrix_ref.o auxfunc.o drng.o SIG_AlgorithmInstance.o KAT_SIG.o
BENCH_OBJS = gf256.o matrix.o uov/blas_matrix_ref.o auxfunc.o drng.o SIG_AlgorithmInstance.o bench_sign.o

all: $(TARGET)

bench: $(BENCH)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BENCH): $(BENCH_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

uov/%.o: uov/%.c
	$(CC) $(CFLAGS) -Iuov -c $< -o $@

clean:
	rm -f $(OBJS) $(BENCH_OBJS) $(TARGET) $(BENCH) uov/*.o

.PHONY: all bench clean
