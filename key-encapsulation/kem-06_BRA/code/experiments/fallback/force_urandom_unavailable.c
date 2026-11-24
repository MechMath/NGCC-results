#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

/*
 * Local fault-injection shim for the otherwise unmodified BRA demo.
 * It returns the same observable condition as the original code's
 * "cannot open /dev/urandom" branch: fopen(...,"r") fails with ENOENT.
 * Other files are opened normally.
 */
FILE *fopen(const char *path, const char *mode) {
  static FILE *(*real_fopen)(const char *, const char *);
  if (!real_fopen) {
    real_fopen = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen");
  }
  if (strcmp(path, "/dev/urandom") == 0 && strcmp(mode, "r") == 0) {
    return NULL;
  }
  return real_fopen(path, mode);
}
