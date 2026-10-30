#!/usr/bin/env python3
"""Write the hand-made starter seeds of the server-less harnesses (no valkey build needed).

usage: gen-seeds-static.py <out-dir (repo mayhem/)>
  fuzz_resp_reader/testsuite/*   RESP2/RESP3 reply streams (first two bytes: mode, chunk size)
  fuzz_acl_rules/testsuite/*     ACL rule lines + a final command line to permission-check
  fuzz_lua_libs/testsuite/*      one input per routine (first byte selects it)
(The other targets' seeds come from gen-seeds.py, which needs a real server.)
"""
import os, struct, sys

out = sys.argv[1]


def wr(target, name, data):
    d = os.path.join(out, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "wb").write(data)


def resp(*a):
    b = b"*%d\r\n" % len(a)
    for x in a:
        b += b"$%d\r\n%s\r\n" % (len(x), x)
    return b


# --- fuzz_resp_reader: byte0 = mode (0x80 encoder, 0x40|n maxelements), byte1 = chunk size (0 = whole)
rr = "fuzz_resp_reader"
for name, body in [
    ("simple", b"+OK\r\n-ERR boom\r\n:42\r\n$5\r\nhello\r\n$-1\r\n"),
    ("array", b"*3\r\n$3\r\nfoo\r\n:-7\r\n*2\r\n+a\r\n+b\r\n"),
    ("nested", b"*2\r\n*2\r\n*1\r\n:1\r\n$0\r\n\r\n*-1\r\n"),
    ("resp3_map", b"%2\r\n+k1\r\n:1\r\n+k2\r\n,3.5\r\n"),
    ("resp3_set_push", b"~3\r\n#t\r\n#f\r\n_\r\n>2\r\n+message\r\n$2\r\nhi\r\n"),
    ("resp3_misc", b"(3492890328409238509324850943850943825024385\r\n=15\r\ntxt:Some string\r\n,inf\r\n,-inf\r\n,nan\r\n"),
    ("resp3_attr", b"|1\r\n+ttl\r\n:3600\r\n$3\r\nbar\r\n"),
]:
    wr(rr, name, b"\x00\x00" + body)
wr(rr, "chunked_by_one", b"\x00\x01" + b"*2\r\n$3\r\nfoo\r\n%1\r\n+a\r\n:1\r\n")
wr(rr, "max_elements", b"\x43\x00" + b"*9\r\n:1\r\n")
wr(rr, "encode_command", b"\x80\x00" + b"SET\x00key\x00value with spaces")
wr(rr, "encode_binary", b"\x80\x00" + b"GET\x00\x00\xff\r\n\x01")

# --- fuzz_acl_rules: rule lines, then the command line to check
ac = "fuzz_acl_rules"
for name, text in [
    ("basic", "on\n>secret\n~key:*\n+@read\n-debug\nget key:1"),
    ("allow_all", "on\nnopass\n~*\n&*\n+@all\nset foo bar"),
    ("subcommands", "on\nresetkeys\n~data:*\n-@all\n+client|id\n+config|get\n+acl|whoami\nconfig get maxmemory"),
    ("selectors", "on\n~read:*\n%R~read:*\n%W~write:*\n(+set ~write:*)\n(+get %R~other:*)\n+get\nset write:1 v"),
    ("categories", "on\n+@all\n-@dangerous\n+@keyspace\n-@write\nflushall"),
    ("channels", "on\nresetchannels\n&news.*\n+publish\n+subscribe\npublish news.sport hi"),
    ("hashed_pw", "on\n#5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n<x\nnopass\nresetpass\nping"),
    ("firstarg", "on\n+select\n+set|key1\n+set|key2\nset key1 v"),
    ("reset", "on\nreset\nallkeys\nallchannels\nallcommands\nsanitize-payload\nget a"),
]:
    wr(ac, name, text.encode())

# --- fuzz_lua_libs: byte0 = routine
ll = "fuzz_lua_libs"
wr(ll, "cjson_object", b"\x00" + b'{"a":[1,2,{"b":null}],"c":"str\\u00e9","d":1.5e300,"e":true}')
wr(ll, "cjson_deep", b"\x00" + b"[" * 40 + b"1" + b"]" * 40)
wr(ll, "cjson_numbers", b"\x00" + b"[0, -0, 1e999, 123456789012345678, 0.1, NaN, Infinity]")
wr(ll, "msgpack_map", b"\x01" + bytes([0x82, 0xa1]) + b"a" + bytes([0x93, 0x01, 0x02, 0x03, 0xa1]) + b"b" + bytes([0xc3]))
wr(ll, "msgpack_num", b"\x01" + bytes([0x94, 0xcb]) + struct.pack(">d", 2.5) + bytes([0xd3]) + struct.pack(">q", -5) + bytes([0xcd, 0x01, 0x00, 0xc0]))
wr(ll, "msgpack_str", b"\x01" + bytes([0xd9, 0x05]) + b"hello" + bytes([0xc4, 0x02, 0x00, 0xff]))
wr(ll, "struct_unpack", b"\x02" + b"\x08" + b">I2hbc0s" + struct.pack(">I2hb", 7, 1, -2, 3) + b"abcdef")
wr(ll, "struct_pack_size", b"\x03" + b"<!4 i2 s5 d")
wr(ll, "msgpack_one", b"\x04" + bytes([0x92, 0x01, 0x02, 0x03]))
wr(ll, "msgpack_limit", b"\x05" + bytes([0x02, 0x00]) + bytes([0x01, 0x02, 0x03]))
wr(ll, "lua_source", b"\x06" + b"local t = {} for i = 1, 10 do t[#t+1] = redis.call('GET', KEYS[i]) end return cjson.encode(t)")
wr(ll, "lua_source2", b"\x06" + b"function f(a, ...) local s = string.format('%d-%s', a, tostring(...)) return s:rep(2) end return f(ARGV[1], 'x')")
wr(ll, "bit_ops", b"\x0a" + struct.pack("<ii", 0x12345678, 5))
