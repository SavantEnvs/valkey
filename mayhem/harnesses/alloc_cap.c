/* Emulates a memory-limited host: single allocations above ALLOC_CAP fail with ENOMEM like they
 * would under a real RLIMIT_AS, instead of tripping the sanitizer's "allocation too big" abort
 * on the loader's try-allocation paths. Linked with -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc. */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#define ALLOC_CAP ((size_t)1 << 30)

void *__real_malloc(size_t n);
void *__real_calloc(size_t n, size_t m);
void *__real_realloc(void *p, size_t n);

void *__wrap_malloc(size_t n) {
    if (n > ALLOC_CAP) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_malloc(n);
}

void *__wrap_calloc(size_t n, size_t m) {
    if (m != 0 && n > ALLOC_CAP / m) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_calloc(n, m);
}

void *__wrap_realloc(void *p, size_t n) {
    if (n > ALLOC_CAP) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_realloc(p, n);
}
