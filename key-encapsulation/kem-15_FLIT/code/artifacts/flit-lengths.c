#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t (*len_fn)(void);

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s LIBRARY\n", argv[0]);
        return 2;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen: %s\n", dlerror());
        return 3;
    }
    const char *names[] = {
        "kem_get_pk_len_bytes",
        "kem_get_sk_len_bytes",
        "kem_get_ss_len_bytes",
        "kem_get_ct_len_bytes",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        len_fn fn = (len_fn)dlsym(handle, names[i]);
        if (fn == NULL) {
            fprintf(stderr, "dlsym(%s): %s\n", names[i], dlerror());
            dlclose(handle);
            return 4;
        }
        printf("%s=%llu\n", names[i], (unsigned long long)fn());
    }
    dlclose(handle);
    return 0;
}
