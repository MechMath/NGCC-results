#define _GNU_SOURCE

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

static void *(*real_malloc)(size_t);
static _Atomic int armed;
static _Atomic unsigned long fault_count;

void arm_malloc_fault(void)
{
    atomic_store_explicit(&fault_count, 0, memory_order_relaxed);
    atomic_store_explicit(&armed, 1, memory_order_release);
}

unsigned long malloc_fault_count(void)
{
    return atomic_load_explicit(&fault_count, memory_order_acquire);
}

void *malloc(size_t size)
{
    if (real_malloc == NULL) {
        real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
    }

    if (size >= 4096 &&
        atomic_exchange_explicit(&armed, 0, memory_order_acq_rel) != 0) {
        atomic_fetch_add_explicit(&fault_count, 1, memory_order_release);
        return NULL;
    }

    return real_malloc(size);
}
