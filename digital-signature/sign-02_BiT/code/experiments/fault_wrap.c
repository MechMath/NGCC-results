#include <stddef.h>

void *__real_malloc(size_t size);

static int armed;
static size_t fail_size;
static size_t fail_threshold;
static int use_threshold;
static unsigned long fault_count;
static size_t observed_sizes[16];
static unsigned long observed_count;
static int logging;

void fault_log_enable(int enabled)
{
    logging = enabled;
    observed_count = 0;
}

size_t fault_observed_size(unsigned long index)
{
    return index < observed_count ? observed_sizes[index] : 0;
}

unsigned long fault_observed_count(void)
{
    return observed_count;
}

void fault_arm(size_t size)
{
    armed = 1;
    fail_size = size;
    use_threshold = 0;
    fault_count = 0;
}

void fault_arm_threshold(size_t threshold)
{
    armed = 1;
    fail_threshold = threshold;
    use_threshold = 1;
    fault_count = 0;
}

unsigned long fault_count_get(void)
{
    return fault_count;
}

void *__wrap_malloc(size_t size)
{
    if (logging && observed_count < 16)
        observed_sizes[observed_count++] = size;
    if (armed && ((use_threshold && size >= fail_threshold) ||
                  (!use_threshold && size == fail_size))) {
        armed = 0;
        fault_count++;
        return NULL;
    }
    return __real_malloc(size);
}
