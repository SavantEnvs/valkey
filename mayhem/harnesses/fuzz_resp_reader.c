/* Feeds bytes to libvalkey's RESP2/RESP3 reply parser (the code valkey-cli, valkey-benchmark and every
 * libvalkey client use to decode server replies). The first byte picks how the input is chunked, so the
 * reader's incremental state machine is exercised, and which reply-object builder is used. A second
 * mode serializes the input as a command with valkeyFormatCommandArgv and parses that back. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <valkey/valkey.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void drain(valkeyReader *r) {
    void *reply = NULL;
    while (valkeyReaderGetReply(r, &reply) == VALKEY_OK && reply != NULL) {
        freeReplyObject(reply);
        reply = NULL;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    uint8_t mode = data[0];
    size_t chunk = data[1];
    data += 2;
    size -= 2;

    if (mode & 0x80) {
        /* Command encoder: split the input on NUL bytes into argv, encode, and read it back as a reply
         * stream (an encoded command is a RESP array of bulk strings). */
        const char *argv[16];
        size_t argvlen[16];
        int argc = 0;
        size_t start = 0;
        for (size_t i = 0; i <= size && argc < 16; i++) {
            if (i == size || data[i] == 0) {
                argv[argc] = (const char *)data + start;
                argvlen[argc] = i - start;
                argc++;
                start = i + 1;
            }
        }
        char *cmd = NULL;
        long long len = valkeyFormatCommandArgv(&cmd, argc, argv, argvlen);
        if (len <= 0 || cmd == NULL) return -1;
        valkeyReader *r = valkeyReaderCreate();
        if (valkeyReaderFeed(r, cmd, (size_t)len) == VALKEY_OK) drain(r);
        valkeyReaderFree(r);
        free(cmd);
        return 0;
    }

    valkeyReader *r = valkeyReaderCreate();
    if (r == NULL) return -1;
    if (mode & 0x40) r->maxelements = 1 + (long long)(mode & 0x3f);
    if (chunk == 0) chunk = size ? size : 1;
    for (size_t off = 0; off < size; off += chunk) {
        size_t n = size - off < chunk ? size - off : chunk;
        if (valkeyReaderFeed(r, (const char *)data + off, n) != VALKEY_OK) break;
        drain(r);
        if (r->err) break;
    }
    valkeyReaderFree(r);
    return 0;
}
