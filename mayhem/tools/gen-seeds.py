#!/usr/bin/env python3
"""Regenerate the starter seed corpora under mayhem/<target>/testsuite from a normal valkey build.

usage: gen-seeds.py <valkey-server> <valkey-cli> <out-dir (repo mayhem/)>
Starts a throwaway server, builds one key per interesting RDB encoding, and writes
  fuzz_rdb_object/testsuite/*   DUMP payloads minus their 10-byte (version + CRC64) footer
  fuzz_encodings/testsuite/*    raw listpack/intset/ziplist/zipmap blobs and an LZF stream
  fuzz_util_parse/testsuite/*   a few hand-written inputs per routine
  check_rdb/testsuite/*  RDB files
  check_aof/testsuite/*  AOF files (RDB-preamble base, incremental, plain)
"""
import os, shutil, socket, struct, subprocess, sys, tempfile, time

server, cli, out = sys.argv[1:4]
PORT = 7791


def resp(*a):
    b = b"*%d\r\n" % len(a)
    for x in a:
        x = x if isinstance(x, bytes) else str(x).encode()
        b += b"$%d\r\n%s\r\n" % (len(x), x)
    return b


class C:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT))
        self.f = self.s.makefile("rb")

    def __call__(self, *a):
        self.s.sendall(resp(*a))
        return self.read()

    def read(self):
        l = self.f.readline()
        t, rest = l[:1], l[1:-2]
        if t == b"$":
            n = int(rest)
            return None if n < 0 else self.f.read(n + 2)[:-2]
        if t == b"*":
            return [self.read() for _ in range(int(rest))]
        if t == b"-":
            raise RuntimeError(rest)
        return rest


def wr(d, name, data):
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, name), "wb").write(data)


def start(extra, d):
    p = subprocess.Popen([server, "--port", str(PORT), "--save", "", "--dir", d] + extra,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            return p, C()
        except OSError:
            time.sleep(0.1)
    raise SystemExit("server did not start")


def stop(p, c):
    try:
        c("shutdown", "nosave")
    except Exception:
        pass
    p.wait()


work = tempfile.mkdtemp()
p, c = start([], work)
c("flushall")
c("set", "str_short", "hello")
c("set", "str_int", "12345")
c("set", "str_int_big", "-9223372036854775807")
c("set", "str_lzf", "abc" * 400)
c("set", "str_hll_like", b"HYLL" + bytes(12))
c("pfadd", "hll", *[f"e{i}" for i in range(50)])
c("rpush", "list_small", "a", "b", "c", "12", "hello world")
c("rpush", "list_big", *[f"element-{i:05d}" * 4 for i in range(1500)])
c("sadd", "set_int", 1, 2, 3, 70000, 5000000000)
c("sadd", "set_lp", "x", "y", "z")
c("sadd", "set_ht", *[f"member{i}" for i in range(300)])
c("zadd", "zset_lp", 1, "one", 2.5, "two", -3, "three")
c("zadd", "zset_sl", *sum([[i * 0.5, f"m{i}"] for i in range(300)], []))
c("hset", "hash_lp", "f1", "v1", "f2", "v2", "n", "42")
c("hset", "hash_ht", *sum([[f"field{i}", f"value{i}"] for i in range(300)], []))
c("hset", "hash_ttl", "a", "1", "b", "2")
c("hexpire", "hash_ttl", 100000, "fields", 1, "a")
c("xadd", "stream", "1-1", "a", "1")
c("xadd", "stream", "2-1", "b", "2", "c", "3")
c("xgroup", "create", "stream", "g1", "0")
c("xreadgroup", "group", "g1", "alice", "count", "1", "streams", "stream", ">")

seeds = {}
for k in c("keys", "*"):
    k = k.decode()
    payload = c("dump", k)
    seeds[k] = payload
    wr(f"{out}/fuzz_rdb_object/testsuite", k, payload[:-10])

# raw blobs for the encoding validators, cut out of the DUMP payloads (type byte, length, blob, footer)
def blob_of(payload):
    body = payload[1:-10]
    n = body[0]
    if n & 0xC0 == 0:
        return body[1:1 + n]
    if n & 0xC0 == 0x40:
        l = ((n & 0x3F) << 8) | body[1]
        return body[2:2 + l]
    l = struct.unpack(">I", body[1:5])[0]
    return body[5:5 + l]

wr(f"{out}/fuzz_encodings/testsuite", "intset", bytes([2]) + blob_of(seeds["set_int"]))
wr(f"{out}/fuzz_encodings/testsuite", "listpack_set", bytes([0]) + blob_of(seeds["set_lp"]))
wr(f"{out}/fuzz_encodings/testsuite", "listpack_zset", bytes([0]) + blob_of(seeds["zset_lp"]))
wr(f"{out}/fuzz_encodings/testsuite", "listpack_hash", bytes([0]) + blob_of(seeds["hash_lp"]))

def ziplist(entries):
    body = b"".join(entries) + b"\xff"
    hdr = struct.pack("<IIH", 10 + len(body) + 0, 10, len(entries))
    z = bytearray(hdr + body)
    z[0:4] = struct.pack("<I", len(z))
    tail = 10
    for e in entries[:-1]:
        tail += len(e)
    z[4:8] = struct.pack("<I", tail)
    return bytes(z)

zl = ziplist([b"\x00\x01a", b"\x03\x02bb", b"\x05\xf3"])
wr(f"{out}/fuzz_encodings/testsuite", "ziplist", bytes([1]) + zl)
wr(f"{out}/fuzz_encodings/testsuite", "zipmap", bytes([3]) + b"\x02\x03foo\x03\x00bar\x01k\x01\x00v\xff")
raw = seeds["str_lzf"]
assert raw[1] == 0xC3
body = raw[2:-10]
def rdb_len(b):
    n = b[0]
    if n & 0xC0 == 0:
        return n, 1
    if n & 0xC0 == 0x40:
        return ((n & 0x3F) << 8) | b[1], 2
    return struct.unpack(">I", b[1:5])[0], 5
clen, o1 = rdb_len(body)
ulen, o2 = rdb_len(body[o1:])
comp = body[o1 + o2:o1 + o2 + clen]
wr(f"{out}/fuzz_encodings/testsuite", "lzf", bytes([4]) + struct.pack("<H", ulen - 1) + comp)

ut = f"{out}/fuzz_util_parse/testsuite"
for i, (name, data) in enumerate([
    ("glob_classes", b"\x00\x0ah[a-c]llo*?h" + b"hello world"),
    ("glob_nocase", b"\x80\x06H*L?O*" + b"hello world"),
    ("glob_prefix", b"\x01\x04abc*abcdef"),
    ("splitargs", b"\x02set \"key\\x41\" 'va\\'lue' plain"),
    ("splitargs_esc", b"\x02get \"a\\n\\t\\x00b\" ''"),
    ("int", b"\x03-9223372036854775808"),
    ("uint", b"\x03" + b"18446744073709551615"),
    ("float", b"\x041.7976931348623157e308"),
    ("float_inf", b"\x04-inf"),
    ("mem", b"\x05" + b"1gb"),
    ("version", b"\x05" + b"255.255.255"),
    ("d2s", b"\x06" + struct.pack("<d", 3.14159265358979)),
    ("sds", b"\x07" + b"  a,b;c \"quoted\"\r\n"),
]):
    wr(ut, name, data)

# RDB / AOF files for the file-input checkers
c("set", "plain", "value")
c("save")
shutil.copy(os.path.join(work, "dump.rdb"), "/tmp/dump-full.rdb")
wr(f"{out}/check_rdb/testsuite", "all-encodings.rdb", open("/tmp/dump-full.rdb", "rb").read())
c("flushall")
c("set", "k", "v")
c("save")
wr(f"{out}/check_rdb/testsuite", "one-key.rdb", open(os.path.join(work, "dump.rdb"), "rb").read())
c("flushall")
c("save")
wr(f"{out}/check_rdb/testsuite", "empty.rdb", open(os.path.join(work, "dump.rdb"), "rb").read())
stop(p, c)

shutil.rmtree(work)
work = tempfile.mkdtemp()
p, c = start(["--appendonly", "yes", "--aof-use-rdb-preamble", "no"], work)
c("set", "a", "1")
c("rpush", "l", "x", "y")
c("hset", "h", "f", "v")
c("incr", "a")
c("zadd", "z", 1, "m")
c("bgrewriteaof")
time.sleep(1.5)
c("set", "after", "rewrite")
c("expire", "after", 1000)
time.sleep(1.2)
stop(p, c)
aofdir = os.path.join(work, "appendonlydir")
for f in sorted(os.listdir(aofdir)):
    if f.endswith(".aof"):
        wr(f"{out}/check_aof/testsuite", f.replace("appendonly.aof", "seed"), open(os.path.join(aofdir, f), "rb").read())
shutil.rmtree(work)
