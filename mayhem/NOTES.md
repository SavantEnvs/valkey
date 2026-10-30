# Mayhem layer notes

## What is and is not fuzzed

Eight targets, all original (upstream ships no fuzz targets and there is no legacy `mayhemheroes/valkey`):

| Target | Code under test |
| --- | --- |
| `fuzz_rdb_object` | `rdbLoadObject` deep validation, every value encoding |
| `fuzz_encodings` | listpack, ziplist, intset, zipmap, LZF validation and walking |
| `fuzz_util_parse` | glob matcher, `sdssplitargs`, number and memory-size parsers, sds helpers |
| `fuzz_acl_rules` | ACL rule parser (`ACLSetUser`) and the permission check |
| `fuzz_lua_libs` | the Lua sandbox's bundled cjson, cmsgpack, struct, bit libraries and the Lua compiler |
| `fuzz_resp_reader` | libvalkey's client-side reply parser (`valkeyReader`) and the command encoder |
| `check_rdb`, `check_aof` | the real `valkey-check-rdb` / `valkey-check-aof` entry points (file input) |

Not covered: the server's request path. `networking.c` (`processInputBuffer`, request parsing),
`processCommand` and the command implementations are not fuzzed. `fuzz_resp_reader` parses
*replies* on the client side; it is not the server's request parser. Replication, cluster bus, modules, TLS
and the scripting engine's `server.call` bridge are also not reached. Eight green targets are not whole-API
coverage.

## Sanitizer checks relaxed

ASan and every UBSan check not listed here stay halting (`-fno-sanitize-recover=all`). Leak detection is off
at build time (`lsan_off.cc`). Relaxed with `-fno-sanitize=<check>`; those bug classes cannot be reported in
the named components:

| Check | Where | Why |
| --- | --- | --- |
| `shift-base` | the whole sanitized server build (`check_rdb`, `check_aof`, and the objects the libFuzzer harnesses link) | `ziplist.c` does `byte << 24` on an `int`, which trips on any 5-byte length encoding |
| `float-cast-overflow` | every file of the bundled Lua rebuilt for `fuzz_lua_libs` | out-of-range double to int casts (table keys, number formatting, cmsgpack's int64 test) |
| `alignment` | `lstring.c` (bundled Lua) | `murmur32` reads unaligned `uint32` words on every string creation |
| `shift-exponent` | `lua_bit.c`, `lua_struct.c` (bundled Lua) | `bit.rol/ror(x, 0)` evaluates `x >> 32`; `struct.unpack("i24")` shifts by `size*8-1 >= 64` |
| `shift-base` | `lua_cmsgpack.c` (bundled Lua) | the int64 decoder shifts a promoted byte into the sign bit (`b << 56`) |

## Allocation cap

`harnesses/alloc_cap.c` is linked into every target with `--wrap=malloc/calloc/realloc`. It fails requests over
1GB with `ENOMEM`, because valkey's loaders use try-allocations that fail gracefully for absurd length claims
and ASan's too-big abort would otherwise kill the process first. It mocks the libc environment only.
