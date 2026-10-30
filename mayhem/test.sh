#!/usr/bin/env bash
#
# mayhem/test.sh — RUN valkey's own functional tests against the normal build that mayhem/build.sh
# left in mayhem/build-normal/. exit 0 = pass.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}


NORMAL="$SRC/mayhem/build-normal"
SERVER="$NORMAL/src/valkey-server"
CLI="$NORMAL/src/valkey-cli"
for f in "$SERVER" "$CLI" "$NORMAL/runtest"; do
  [ -x "$f" ] || { echo "missing $f — mayhem/build.sh did not build it" >&2; emit_ctrf valkey 0 1 0; exit 1; }
done

PASSED=0
FAILED=0
SKIPPED=0

# --- 1) Known-answer probes on the RESTORE path --------------------------------------------------
# Each payload is a DUMP of a key built by a real server (hex), followed by the value the key must
# read back as. A corrupted payload must be refused.
PORT=$(( 20000 + $$ % 20000 ))
WORK="$(mktemp -d)"
"$SERVER" --port "$PORT" --save "" --appendonly no --dir "$WORK" --daemonize no >"$WORK/server.log" 2>&1 &
SPID=$!
cleanup() { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT
up=0
for _ in $(seq 1 100); do
  if [ "$("$CLI" -p "$PORT" ping 2>/dev/null)" = "PONG" ]; then up=1; break; fi
  kill -0 "$SPID" 2>/dev/null || break
  sleep 0.1
done

vk() { "$CLI" -p "$PORT" "$@" 2>&1; }
restore() {  # restore <key> <hex payload>
  local bytes; bytes="$(printf '%s' "$2" | sed 's/../\\x&/g')"
  printf "$bytes" | "$CLI" -p "$PORT" -x restore "$1" 0 2>&1
}
expect() {  # expect <name> <want> <got>
  if [ "$3" = "$2" ]; then PASSED=$((PASSED+1)); else FAILED=$((FAILED+1)); echo "FAIL $1: want [$2] got [$3]" >&2; fi
}

if [ "$up" = 1 ]; then
  expect "ping" "PONG" "$(vk ping)"
  expect "set" "OK" "$(vk set k hello)"
  expect "get" "hello" "$(vk get k)"
  expect "incr" "6" "$( (vk set n 5 >/dev/null; vk incr n) )"
  expect "restore string" "OK" "$(restore s 000568656c6c6f5100c587ab9406f9ae77)"
  expect "restored string value" "hello" "$(vk get s)"
  expect "restore int string" "OK" "$(restore i 00c1393051003b619ec5f03186c4)"
  expect "restored int string value" "12345" "$(vk get i)"
  expect "restore list" "OK" "$(restore l 12010210100000000300816102816202816302ff51006eedcdeef6fedce3)"
  expect "restored list" "a b c" "$(vk lrange l 0 -1 | tr '\n' ' ' | sed 's/ $//')"
  expect "restore intset" "OK" "$(restore si 0b0e0200000003000000010002000300510003f728000ea3c366)"
  expect "restored intset" "1 2 3" "$(vk smembers si | sort -n | tr '\n' ' ' | sed 's/ $//')"
  expect "restore listpack set" "OK" "$(restore ss 140d0d0000000200817802817902ff5100d3ba92fa49aaf07e)"
  expect "restored listpack set" "x y" "$(vk smembers ss | sort | tr '\n' ' ' | sed 's/ $//')"
  expect "restore zset" "OK" "$(restore z 1115150000000400836f6e650401018374776f040201ff5100cda33add78b156b5)"
  expect "restored zset" "one 1 two 2" "$(vk zrange z 0 -1 withscores | tr '\n' ' ' | sed 's/ $//')"
  expect "restore hash" "OK" "$(restore h 101717000000040082663103827631038266320382763203ff5100a50d38ee76192cc1)"
  expect "restored hash" "f1 v1 f2 v2" "$(vk hgetall h | tr '\n' ' ' | sed 's/ $//')"
  # same string payload with its last CRC byte flipped
  bad="$(restore bad 000568656c6c6f5100c587ab9406f9ae78)"
  case "$bad" in *"checksum are wrong"*) PASSED=$((PASSED+1)) ;; *) FAILED=$((FAILED+1)); echo "FAIL corrupt payload accepted: $bad" >&2 ;; esac
  expect "corrupt payload left no key" "0" "$(vk exists bad)"
  expect "list length after restore" "3" "$(vk llen l)"
else
  FAILED=$((FAILED+1)); echo "FAIL valkey-server did not come up:" >&2; tail -5 "$WORK/server.log" >&2
fi
cleanup; trap - EXIT

# --- 2) valkey's own Tcl test-suite (a representative, fast subset) ------------------------------
cd "$NORMAL"
TESTS="unit/type/incr unit/type/string unit/type/hash unit/type/set unit/type/zset unit/type/list-2 \
unit/dump unit/hyperloglog unit/keyspace unit/bitops unit/geo unit/expire unit/sort unit/scan"
args=()
for t in $TESTS; do args+=(--single "$t"); done
LOG="$(mktemp)"
timeout 2400 ./runtest --clients 4 --timeout 600 "${args[@]}" >"$LOG" 2>&1
rc=$?
TCL_OK=$(grep -c '^\[ok\]:' "$LOG")
TCL_ERR=$(grep -cE '^\[(err|exception)\]:' "$LOG")
TCL_SKIP=$(grep -cE '^\[(skip|ignore)\]:' "$LOG")
PASSED=$((PASSED+TCL_OK)); FAILED=$((FAILED+TCL_ERR)); SKIPPED=$((SKIPPED+TCL_SKIP))
if [ "$rc" -ne 0 ] && [ "$TCL_ERR" -eq 0 ]; then FAILED=$((FAILED+1)); fi
if [ "$TCL_OK" -eq 0 ]; then FAILED=$((FAILED+1)); fi
if [ "$FAILED" -ne 0 ]; then grep -E '^\[(err|exception)\]|^Expected|^\*\*\*' "$LOG" | head -40 >&2; tail -15 "$LOG" >&2; fi
rm -f "$LOG"

cd "$SRC"
emit_ctrf valkey "$PASSED" "$FAILED" "$SKIPPED"
