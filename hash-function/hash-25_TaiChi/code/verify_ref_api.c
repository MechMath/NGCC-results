#define _GNU_SOURCE
#include "CryptHash_AlgorithmInstance.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#ifndef TAICHI_BITS
#error "Define TAICHI_BITS as 512, 768, or 1024"
#endif

#define DIGEST_BYTES (TAICHI_BITS / 8)
#define MESSAGE_BYTES (128ULL << 20)
#define HEADROOM_BYTES (16ULL << 20)

static unsigned long long virtual_size_bytes(void)
{
    FILE *f = fopen("/proc/self/statm", "r");
    unsigned long long total_pages = 0;
    unsigned long long resident_pages = 0;

    if (f == NULL ||
        fscanf(f, "%llu %llu", &total_pages, &resident_pages) != 2) {
        perror("read /proc/self/statm");
        exit(2);
    }
    fclose(f);
    return total_pages * (unsigned long long)sysconf(_SC_PAGESIZE);
}

int main(int argc, char **argv)
{
    unsigned char sentinel[DIGEST_BYTES];
    unsigned char digest[DIGEST_BYTES];
    unsigned char *message;
    struct rlimit limit;
    unsigned long long current_vsize;
    unsigned long long new_limit;
    void *allocation_probe;
    int no_limit;
    int probe_null;
    int rc;

    no_limit = argc == 2 && strcmp(argv[1], "--no-limit") == 0;
    message = mmap(NULL, MESSAGE_BYTES, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (message == MAP_FAILED) {
        perror("mmap message");
        return 2;
    }

    /* Materialize a valid, readable message before reducing the address limit. */
    memset(message, 0x42, MESSAGE_BYTES);
    memset(sentinel, 0xa5, sizeof(sentinel));
    memcpy(digest, sentinel, sizeof(digest));

    current_vsize = virtual_size_bytes();
    new_limit = current_vsize + HEADROOM_BYTES;
    if (getrlimit(RLIMIT_AS, &limit) != 0) {
        perror("getrlimit");
        return 2;
    }
    if (!no_limit) {
        limit.rlim_cur = (rlim_t)new_limit;
        if (setrlimit(RLIMIT_AS, &limit) != 0) {
            perror("setrlimit");
            return 2;
        }
    }

    if (no_limit) {
        probe_null = -1;
    } else {
        allocation_probe = malloc(MESSAGE_BYTES);
        probe_null = allocation_probe == NULL;
        free(allocation_probe);
    }

    rc = CryptHash(TAICHI_BITS, message, MESSAGE_BYTES * 8ULL, digest);
    printf("bits=%d rc=%d message_valid=%d probe_malloc_null=%d "
           "digest_unchanged=%d vsize=%llu limit=%llu\n",
           TAICHI_BITS, rc,
           message[0] == 0x42 && message[MESSAGE_BYTES - 1] == 0x42,
           probe_null,
           memcmp(digest, sentinel, sizeof(digest)) == 0,
           current_vsize, new_limit);
    return 0;
}
