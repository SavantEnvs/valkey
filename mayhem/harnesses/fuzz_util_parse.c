/* Exercises valkey's text/number parsing helpers (glob matcher, argument splitter, string<->number
 * conversions). The first input byte picks the routine, the rest is its input. Every variable-length
 * argument is copied to its own exact-size heap buffer so ASan sees any over-read. */
#include "server.h"
#include <math.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static char *exact_copy(const uint8_t *p, size_t n, int nul_terminate) {
    char *buf = zmalloc(n + 1);
    memcpy(buf, p, n);
    if (nul_terminate) buf[n] = '\0';
    return nul_terminate ? buf : zrealloc(buf, n ? n : 1);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    uint8_t op = data[0] & 0x0f;
    int flag = data[0] >> 7;
    data++;
    size--;

    switch (op) {
    case 0:
    case 1: { /* KEYS/SCAN-style glob match: split the input into pattern and subject */
        if (size < 1) return -1;
        size_t plen = data[0] % size;
        const uint8_t *rest = data + 1;
        size_t rsize = size - 1;
        if (plen > rsize) plen = rsize;
        char *pat = exact_copy(rest, plen, 1); /* callers pass sds patterns: the glob matcher peeks at pattern[1] */
        char *str = exact_copy(rest + plen, rsize - plen, 0);
        stringmatchlen(pat, (int)plen, str, (int)(rsize - plen), flag);
        prefixmatchlen(pat, (int)plen, str, (int)(rsize - plen), flag);
        zfree(pat);
        zfree(str);
        break;
    }
    case 2: { /* config-file / inline-protocol argument splitting */
        char *line = exact_copy(data, size, 1);
        int argc = 0;
        sds *argv = sdssplitargs(line, &argc);
        if (argv) {
            sds joined = sdsempty();
            for (int j = 0; j < argc; j++) joined = sdscatrepr(joined, argv[j], sdslen(argv[j]));
            sdsfree(joined);
            sdsfreesplitres(argv, argc);
        }
        zfree(line);
        break;
    }
    case 3: { /* integer parsing */
        char *str = exact_copy(data, size, 1);
        long long ll;
        unsigned long long ull;
        long l;
        string2ll(str, size, &ll);
        string2ull(str, size, &ull);
        string2l(str, size, &l);
        string2ull_base16_async_signal_safe(str, size, &ull);
        zfree(str);
        break;
    }
    case 4: { /* floating point parsing */
        char *str = exact_copy(data, size, 0);
        long double ld;
        double d;
        string2ld(str, size, &ld);
        string2d(str, size, &d);
        zfree(str);
        break;
    }
    case 5: { /* memory size parsing ("1gb") and version strings */
        char *str = exact_copy(data, size, 1);
        int err = 0;
        memtoull(str, &err);
        version2num(str);
        zfree(str);
        break;
    }
    case 6: { /* number -> string round trips */
        if (size < sizeof(double)) return -1;
        double d;
        long double ld;
        long long ll;
        memcpy(&d, data, sizeof(d));
        char buf[MAX_LONG_DOUBLE_CHARS + 64];
        int n = d2string(buf, sizeof(buf), d);
        if (n > 0) {
            double back;
            string2d(buf, (size_t)n, &back);
        }
        fixedpoint_d2string(buf, sizeof(buf), d, data[0] % 18);
        ld = (long double)d;
        n = ld2string(buf, sizeof(buf), ld, (ld2string_mode)(data[0] % 3));
        if (n > 0 && data[0] % 3 != LD_STR_HEX) {
            long double back;
            string2ld(buf, (size_t)n, &back);
        }
        if (!isnan(d)) double2ll(d, &ll); /* callers reject NaN scores before converting */
        break;
    }
    default: { /* sds helpers used while building replies and parsing options */
        char *str = exact_copy(data, size, 0);
        sds s = sdsnewlen(str, size);
        sds r = sdscatrepr(sdsempty(), s, sdslen(s));
        sdstolower(s);
        sds t = sdstrim(sdsdup(s), " \t\r\n\"'");
        int count = 0;
        sds *parts = sdssplitlen(str, (ssize_t)size, ",;", 2, &count);
        if (parts) sdsfreesplitres(parts, count);
        sdsfree(t);
        sdsfree(r);
        sdsfree(s);
        zfree(str);
        break;
    }
    }
    return 0;
}
