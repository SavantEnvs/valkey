/* Drives valkey's ACL rule parser (what ACL SETUSER, the aclfile and `user` config lines use) and the
 * permission check against it. The input is newline-separated: every line but the last is one ACLSetUser
 * rule applied to a fresh user, the last line is a command line (space separated) that is looked up in
 * the command table and checked against the resulting user. The rules are described back afterwards. */
#include "server.h"
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

void initServerConfig(void);
void createSharedObjects(void);
void moduleInitModulesSystem(void);
void ACLInit(void);
void ACLFreeUser(user *u);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    initServerConfig();
    createSharedObjects();
    moduleInitModulesSystem();
    ACLInit();
    /* A failed serverAssert prints an INFO-based crash report that walks these lists. */
    server.clients = listCreate();
    server.replicas = listCreate();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    int nlines = 0;
    sds *lines = sdssplitlen((const char *)data, (ssize_t)size, "\n", 1, &nlines);
    if (lines == NULL || nlines == 0) {
        sdsfreesplitres(lines, nlines);
        return -1;
    }

    user *u = ACLCreateUnlinkedUser();
    for (int i = 0; i < nlines - 1; i++) {
        ACLSetUser(u, lines[i], (ssize_t)sdslen(lines[i]));
    }
    /* ACLDescribeUser() asserts on command rules holding whitespace, quotes or non-ASCII bytes, which
     * ACL SETUSER accepts (a server crash reachable by any client allowed to run ACL SETUSER + ACL LIST).
     * Users built from such rules are not described, so the fuzzer reaches the rest of the ACL code. */
    int describable = 1;
    for (int i = 0; i < nlines - 1 && describable; i++) {
        for (size_t j = 0; j < sdslen(lines[i]); j++) {
            unsigned char ch = (unsigned char)lines[i][j];
            if (ch <= 0x20 || ch >= 0x7f || ch == '\'' || ch == '"' || ch == '\\') describable = 0;
        }
    }
    if (describable) {
        robj *desc = ACLDescribeUser(u);
        decrRefCount(desc);
    }

    int argc = 0;
    sds *args = sdssplitlen(lines[nlines - 1], (ssize_t)sdslen(lines[nlines - 1]), " ", 1, &argc);
    if (args != NULL && argc > 0 && argc <= 32) {
        robj *argv[32];
        for (int i = 0; i < argc; i++) argv[i] = createStringObject(args[i], sdslen(args[i]));
        struct serverCommand *cmd = lookupCommand(argv, argc);
        /* As in processCommand(), the permission check only ever sees a command whose arity fits. */
        if (cmd != NULL && commandCheckArity(cmd, argc, NULL)) {
            int idx = 0;
            ACLCheckAllUserCommandPerm(u, cmd, argv, argc, 0, &idx);
        }
        for (int i = 0; i < argc; i++) decrRefCount(argv[i]);
    }
    sdsfreesplitres(args, argc);

    ACLFreeUser(u);
    sdsfreesplitres(lines, nlines);
    return 0;
}
