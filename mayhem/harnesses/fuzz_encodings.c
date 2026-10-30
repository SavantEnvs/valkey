/* Feeds untrusted bytes to the compact encodings' integrity validators (listpack, ziplist, intset,
 * zipmap) — the code that guards RESTORE and RDB loading — and, when a blob validates, walks it the
 * way the server does afterwards. The first byte picks the encoding. */
#include "server.h"
#include "listpack.h"
#include "ziplist.h"
#include "intset.h"
#include "zipmap.h"
#include "lzf.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int count_entry(unsigned char *p, unsigned int head_count, void *userdata) {
    (void)p;
    (void)head_count;
    (*(size_t *)userdata)++;
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    uint8_t kind = data[0] % 5;
    data++;
    size--;

    unsigned char *blob = zmalloc(size);
    memcpy(blob, data, size);
    size_t entries = 0;

    switch (kind) {
    case 0: /* listpack; patch the self-reported byte length so inputs reach the entry validator */
        if (size >= 7) {
            blob[0] = size & 0xff;
            blob[1] = (size >> 8) & 0xff;
            blob[2] = (size >> 16) & 0xff;
            blob[3] = (size >> 24) & 0xff;
        }
        if (lpValidateIntegrity(blob, size, count_entry, &entries, data[0] & 1)) {
            for (unsigned char *p = lpFirst(blob); p; p = lpNext(blob, p)) {
                unsigned int slen;
                long long lval;
                lpGetValue(p, &slen, &lval);
            }
            lpLength(blob);
            lpSeek(blob, -1);
        }
        break;
    case 1: /* ziplist (legacy encoding still accepted by RESTORE) */
        if (size >= 11) {
            blob[0] = size & 0xff;
            blob[1] = (size >> 8) & 0xff;
            blob[2] = (size >> 16) & 0xff;
            blob[3] = (size >> 24) & 0xff;
        }
        if (ziplistValidateIntegrity(blob, size, 1, count_entry, &entries)) {
            for (unsigned char *p = ziplistIndex(blob, 0); p; p = ziplistNext(blob, p)) {
                unsigned char *sval;
                unsigned int slen;
                long long lval;
                ziplistGet(p, &sval, &slen, &lval);
            }
            ziplistLen(blob);
        }
        break;
    case 2: /* intset */
        if (intsetValidateIntegrity(blob, size, 1)) {
            intset *is = (intset *)blob;
            uint32_t len = intsetLen(is);
            int64_t v;
            for (uint32_t i = 0; i < len; i++) intsetGet(is, i, &v);
            intsetFind(is, 0);
        }
        break;
    case 3: /* zipmap (very old hash encoding) */
        zipmapValidateIntegrity(blob, size, 1);
        break;
    default: { /* LZF decompression of RDB strings: input[0..1] chooses the output size */
        if (size < 3) break;
        size_t outlen = ((size_t)blob[0] | ((size_t)blob[1] << 8)) + 1;
        unsigned char *out = zmalloc(outlen);
        lzf_decompress(blob + 2, size - 2, out, outlen);
        zfree(out);
        break;
    }
    }
    zfree(blob);
    return 0;
}
