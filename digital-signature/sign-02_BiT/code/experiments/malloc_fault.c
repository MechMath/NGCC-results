#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>

extern void *__libc_malloc(size_t size);

static int armed;
static size_t threshold;
static uint64_t fault_count;
static size_t fault_size;

void bit_fault_arm(size_t min_size)
{
    armed = 1;
    threshold = min_size;
    fault_size = 0;
}

void bit_fault_disarm(void)
{
    armed = 0;
}

uint64_t bit_fault_count(void)
{
    return fault_count;
}

size_t bit_fault_size(void)
{
    return fault_size;
}

void *malloc(size_t size)
{
    if (armed && size >= threshold) {
        armed = 0;
        fault_count++;
        fault_size = size;
        return NULL;
    }
    return __libc_malloc(size);
}
