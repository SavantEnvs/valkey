/* Exercises the C libraries valkey bundles into its Lua scripting sandbox (cjson, cmsgpack, struct, bit)
 * and the Lua source compiler, the code reachable from any EVAL/FCALL script a client sends. The first
 * input byte picks the routine; the rest is its input. Lua errors are caught by lua_pcall (Lua's own
 * error handling); only memory-safety violations and hangs are findings. */
#include <stdint.h>
#include <string.h>
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int luaopen_cjson(lua_State *L);
int luaopen_struct(lua_State *L);
int luaopen_cmsgpack(lua_State *L);
int luaopen_bit(lua_State *L);

static lua_State *L;

static void load_lib(const char *name, lua_CFunction f) {
    lua_pushcfunction(L, f);
    lua_pushstring(L, name);
    lua_call(L, 1, 0);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    L = luaL_newstate();
    load_lib("", luaopen_base);
    load_lib(LUA_TABLIBNAME, luaopen_table);
    load_lib(LUA_STRLIBNAME, luaopen_string);
    load_lib(LUA_MATHLIBNAME, luaopen_math);
    load_lib("cjson", luaopen_cjson);
    load_lib("struct", luaopen_struct);
    load_lib("cmsgpack", luaopen_cmsgpack);
    load_lib("bit", luaopen_bit);
    return 0;
}

/* Calls lib.fn(input[, second]) in protected mode and, for decoders, re-encodes the result. */
static void call2(const char *lib, const char *fn, const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                  const char *enc_lib, const char *enc_fn) {
    int top = lua_gettop(L);
    lua_getglobal(L, lib);
    lua_getfield(L, -1, fn);
    lua_pushlstring(L, (const char *)a, alen);
    int nargs = 1;
    if (b != NULL) {
        lua_pushlstring(L, (const char *)b, blen);
        nargs = 2;
    }
    if (lua_pcall(L, nargs, LUA_MULTRET, 0) == 0 && enc_lib != NULL && lua_gettop(L) > top + 1) {
        lua_getglobal(L, enc_lib);
        lua_getfield(L, -1, enc_fn);
        lua_pushvalue(L, top + 2);
        lua_pcall(L, 1, 1, 0);
    }
    lua_settop(L, top);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return -1;
    uint8_t op = data[0] & 0x0f;
    data++;
    size--;

    switch (op) {
    case 0: call2("cjson", "decode", data, size, NULL, 0, "cjson", "encode"); break;
    case 1: call2("cmsgpack", "unpack", data, size, NULL, 0, "cmsgpack", "pack"); break;
    case 2: {
        /* struct.unpack(fmt, bytes): first byte is the format length. */
        if (size < 1) return -1;
        size_t flen = data[0] % size;
        if (flen > size - 1) flen = size - 1;
        call2("struct", "unpack", data + 1, flen, data + 1 + flen, size - 1 - flen, NULL, NULL);
        break;
    }
    case 3: {
        /* struct.pack(fmt) with no further args plus struct.size(fmt). */
        call2("struct", "size", data, size, NULL, 0, NULL, NULL);
        call2("struct", "pack", data, size, NULL, 0, NULL, NULL);
        break;
    }
    case 4: call2("cmsgpack", "unpack_one", data, size, NULL, 0, NULL, NULL); break;
    case 5: {
        /* cmsgpack.unpack_limit(bytes, limit, offset): limit/offset from the first two bytes. */
        if (size < 2) return -1;
        int top = lua_gettop(L);
        lua_getglobal(L, "cmsgpack");
        lua_getfield(L, -1, "unpack_limit");
        lua_pushlstring(L, (const char *)data + 2, size - 2);
        lua_pushinteger(L, data[0] % 8);
        lua_pushinteger(L, data[1]);
        lua_pcall(L, 3, LUA_MULTRET, 0);
        lua_settop(L, top);
        break;
    }
    case 6: {
        /* Lua compiler only (never runs the chunk, so no infinite loops). Binary chunks are rejected
         * up front: valkey refuses them as well. */
        if (size < 1 || data[0] == '\033') return -1;
        int top = lua_gettop(L);
        luaL_loadbuffer(L, (const char *)data, size, "@fuzz");
        lua_settop(L, top);
        break;
    }
    default: {
        /* bit library on numbers decoded from the input. */
        if (size < 8) return -1;
        int32_t x, y;
        memcpy(&x, data, 4);
        memcpy(&y, data + 4, 4);
        static const char *fns[] = {"tobit", "bnot", "band", "bor", "bxor", "lshift", "rshift", "arshift", "rol", "ror", "bswap", "tohex"};
        const char *fn = fns[(op - 7) % 12];
        int top = lua_gettop(L);
        lua_getglobal(L, "bit");
        lua_getfield(L, -1, fn);
        lua_pushnumber(L, x);
        lua_pushnumber(L, y);
        lua_pcall(L, 2, LUA_MULTRET, 0);
        lua_settop(L, top);
        break;
    }
    }
    return 0;
}
