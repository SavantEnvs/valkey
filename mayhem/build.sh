#!/usr/bin/env bash
#
# mayhem/build.sh — builds, from a pristine copy of the source tree, (1) a sanitized valkey for fuzzing
# and (2) a normal valkey for the functional oracle (mayhem/test.sh). Both builds live in gitignored
# directories under mayhem/, so the upstream tree itself is never written to and re-running is safe.
#
#   mayhem/build-fuzz/     valkey built with $SANITIZER_FLAGS + $DEBUG_FLAGS + libFuzzer coverage
#   mayhem/build-normal/   valkey built with its own default flags (what test.sh drives)
#   mayhem/bin/            fuzz harnesses, their -standalone reproducers, and the file-input targets
#
# Everything is built from the source in the image; nothing is fetched (the bundled deps/ are used).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$SRC"

FUZZ="$SRC/mayhem/build-fuzz"
NORMAL="$SRC/mayhem/build-normal"
BIN="$SRC/mayhem/bin"
HARNESSES="$SRC/mayhem/harnesses"

rm -rf "$FUZZ" "$NORMAL" "$BIN"
mkdir -p "$FUZZ" "$NORMAL" "$BIN"

# Out-of-tree copies: valkey only builds in place, and it must not dirty the source tree.
copy_tree() {
    tar -C "$SRC" --exclude=./.git --exclude=./mayhem -cf - . | tar -C "$1" -xf -
}

OBJ="$FUZZ/harness-obj"
mkdir -p "$OBJ"
# LeakSanitizer off (build-time hook), allocation cap, and the run-once driver as a C object.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OBJ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$HARNESSES/alloc_cap.c" -o "$OBJ/alloc_cap.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

WRAP="-Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc"

# 1) Sanitized valkey. The bundled allocator is replaced by libc malloc so ASan sees every allocation.
#    -fsanitize=fuzzer-no-link adds coverage instrumentation to the library and to the server binary
#    (the server binary doubles as valkey-check-rdb / valkey-check-aof; lsan_off.o and the allocation cap
#    are linked into it, so the checkers' try-allocations fail with ENOMEM like on a memory-limited host
#    instead of tripping ASan's "allocation too big" abort).
copy_tree "$FUZZ"
make -C "$FUZZ/src" -j"$MAYHEM_JOBS" libvalkey.a valkey-server \
    MALLOC=libc BUILD_TLS=no OPTIMIZATION=-O1 \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=shift-base -fsanitize=fuzzer-no-link" \
    LDFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $WRAP $OBJ/alloc_cap.o $OBJ/lsan_off.o"

S="$FUZZ/src"
INCLUDES="-I$S -I$FUZZ/deps/libvalkey/include -I$FUZZ/deps/linenoise -I$FUZZ/deps/hdr_histogram -I$FUZZ/deps/fpconv -I$FUZZ/deps/fast_float -I$FUZZ/deps/lz4"
DEFS="-DLUA_ENABLED -DSTATIC_LUA=1"
LIBS="$S/libvalkey.a $FUZZ/deps/libvalkey/lib/libvalkey.a $FUZZ/deps/hdr_histogram/libhdrhistogram.a $FUZZ/deps/fpconv/libfpconv.a $FUZZ/deps/lz4/liblz4.a -lm -lpthread -ldl"
# 2) libFuzzer harnesses + their standalone reproducers. The server-state harnesses link the whole valkey
#    library; the RESP reader harness needs only libvalkey (the client library); the Lua harness only Lua.
build_harness() { # name, extra compile flags, libs
    local t="$1" cflags="$2" libs="$3"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 $cflags \
        -c "$HARNESSES/$t.c" -o "$OBJ/$t.o"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $WRAP \
        "$OBJ/$t.o" "$OBJ/alloc_cap.o" "$OBJ/lsan_off.o" $libs -o "$BIN/$t"
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS $WRAP \
        "$OBJ/$t.o" "$OBJ/standalone_main.o" "$OBJ/alloc_cap.o" "$OBJ/lsan_off.o" $libs -o "$BIN/$t-standalone"
}
for t in fuzz_rdb_object fuzz_util_parse fuzz_encodings fuzz_acl_rules; do
    build_harness "$t" "$INCLUDES $DEFS" "$LIBS"
done
build_harness fuzz_resp_reader "-I$FUZZ/deps/libvalkey/include" "-Wl,--start-group $LIBS -Wl,--end-group"
# The bundled Lua (5.1 plus cjson/cmsgpack/struct/bit) is full of benign-on-every-common-CPU UB that floods
# UBSan the moment a script touches it, so the Lua objects of this harness are rebuilt with the named
# checks relaxed; ASan and every other UBSan check stay halting:
#   all Lua files   float-cast-overflow  double -> int casts of out-of-range values (table keys, number
#                                        formatting, cmsgpack's IS_INT64_EQUIVALENT test, ...)
#   lstring.c       alignment            murmur32 reads unaligned uint32 words on every string creation
#   lua_bit.c       shift-exponent       bit.rol/ror(x, 0) evaluates `x >> 32`, with the intended result
#   lua_struct.c    shift-exponent       struct.unpack("i24", ...) builds a sign mask with a shift of size*8-1 >= 64
#   lua_cmsgpack.c  shift-base           the int64 decoder shifts a promoted byte into the sign bit (`b << 56`)
LUA_SRC="$FUZZ/deps/lua/src"
LUA_OBJ="$OBJ/lua"
mkdir -p "$LUA_OBJ"
rm -f "$OBJ/liblua-fuzz.a"
for o in $(ar t "$LUA_SRC/liblua.a"); do
    f="${o%.o}"
    case "$f" in
        lstring) extra=",alignment" ;;
        lua_bit) extra=",shift-exponent" ;;
        lua_cmsgpack) extra=",shift-base" ;;
        lua_struct) extra=",shift-exponent" ;;
        *) extra="" ;;
    esac
    $CC $SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize="float-cast-overflow$extra" -fsanitize=fuzzer-no-link -O2 -fPIC \
        -DLUA_ANSI -DENABLE_CJSON_GLOBAL -DLUA_USE_MKSTEMP -I"$LUA_SRC" -c "$LUA_SRC/$f.c" -o "$LUA_OBJ/$o"
done
ar rc "$OBJ/liblua-fuzz.a" "$LUA_OBJ"/*.o
build_harness fuzz_lua_libs "-I$LUA_SRC" "$OBJ/liblua-fuzz.a -lm -ldl"

# 3) File-input targets: valkey's own RDB/AOF checkers (the server binary dispatches on argv[0]).
cp "$S/valkey-server" "$BIN/valkey-check-rdb"
cp "$S/valkey-server" "$BIN/valkey-check-aof"

# 4) Normal valkey for the functional oracle: default flags, no sanitizers, no instrumentation.
copy_tree "$NORMAL"
make -C "$NORMAL/src" -j"$MAYHEM_JOBS" MALLOC=libc BUILD_TLS=no CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
