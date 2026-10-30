/* Feeds a DUMP/RESTORE-style payload (<rdb type byte><object body>) to rdbLoadObject, the same
 * path RESTORE and the RDB loader use. Runs in "restore context" so corrupt payloads are
 * reported as errors instead of terminating the process. */
#include "server.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

void initServerConfig(void);
void createSharedObjects(void);
void moduleInitModulesSystem(void);
static client fake_client;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    initServerConfig();
    createSharedObjects();
    moduleInitModulesSystem();
    fake_client.id = 1;
    server.current_client = &fake_client;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    sds buf = sdsnewlen(data, size);
    rio payload;
    rioInitWithBuffer(&payload, buf);
    int type = rdbLoadObjectType(&payload);
    if (type == -1) {
        sdsfree(buf);
        return -1;
    }
    sds key = sdsnew("fuzzkey");
    robj *obj = rdbLoadObject(type, &payload, key, 0, NULL, RDBFLAGS_NONE, 0);
    sdsfree(key);
    sdsfree(buf);
    if (obj == NULL) return -1;
    robj *keyobj = createStringObject("fuzzkey", 7);
    objectComputeSize(keyobj, obj, 5, 0);
    decrRefCount(keyobj);
    decrRefCount(obj);
    return 0;
}
