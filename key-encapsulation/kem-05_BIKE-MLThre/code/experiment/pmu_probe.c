#define _GNU_SOURCE
#include <errno.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int perf_open(unsigned type, unsigned long long config) {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.type = type;
  attr.size = sizeof(attr);
  attr.config = config;
  attr.disabled = 1;
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  return (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

int main(void) {
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(0, &set);
  if (sched_setaffinity(0, sizeof(set), &set)) {
    fprintf(stderr, "sched_setaffinity: %s\n", strerror(errno));
  }

  struct {
    const char *name;
    unsigned type;
    unsigned long long config;
  } tests[] = {
      {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
      {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
      {"branches", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
      {"branch_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
      {"cache_references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
      {"cache_misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
  };

  int failures = 0;
  for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
    int fd = perf_open(tests[i].type, tests[i].config);
    if (fd < 0) {
      printf("%s: unavailable errno=%d (%s)\n", tests[i].name, errno,
             strerror(errno));
      ++failures;
      continue;
    }
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) ||
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)) {
      printf("%s: ioctl unavailable errno=%d (%s)\n", tests[i].name, errno,
             strerror(errno));
      close(fd);
      ++failures;
      continue;
    }
    volatile unsigned long x = 0;
    for (unsigned long j = 0; j < 1000000; ++j) x += (j & 1);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    unsigned long long count = 0;
    ssize_t n = read(fd, &count, sizeof(count));
    printf("%s: available count=%llu read=%zd\n", tests[i].name, count, n);
    close(fd);
  }
  return failures ? 1 : 0;
}
