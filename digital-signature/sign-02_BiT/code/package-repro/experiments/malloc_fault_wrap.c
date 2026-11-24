#define _GNU_SOURCE
#include <stddef.h>

void *__real_malloc(size_t size);

static int armed;
static size_t minimum_size;
static unsigned long fail_count;

void malloc_fault_arm(size_t size)
{
    armed = 1;
    minimum_size = size;
}

unsigned long malloc_fault_count(void)
{
    return fail_count;
}

void *__wrap_malloc(size_t size)
{
    if (armed && size >= minimum_size) {
        armed = 0;
        fail_count++;
        return NULL;
    }
    return __real_malloc(size);
}
