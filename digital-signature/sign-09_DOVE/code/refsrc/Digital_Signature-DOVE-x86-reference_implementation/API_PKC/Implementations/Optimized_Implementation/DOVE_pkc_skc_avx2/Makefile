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

CFLAGS += -mavx2

TARGET = dove_sign_kat
OBJS = gf256.o matrix.o uov/blas_matrix_avx2.o uov/blas_matrix_ref.o uov/gf16_tabs.o uov/gf256_tabs.o auxfunc.o drng.o SIG_AlgorithmInstance.o KAT_SIG.o
 
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

uov/%.o: uov/%.c
	$(CC) $(CFLAGS) -Iuov -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) uov/*.o

.PHONY: all clean
