#!/bin/sh
# sanitizer-check.sh — RFC 037 §7.5 / RFC 009 §10, RFC 024.
#
# Compiles the real kroopt_ffi.c shim + the vendored HACL* sources it calls,
# together with kroopt_sanitizer_harness.c, under AddressSanitizer +
# UndefinedBehaviorSanitizer (system gcc — the Lean-bundled clang ships no ASan
# runtime), links the Lean runtime so genuine ByteArray objects can be handed to
# the shim, and runs the harness. A clean run means the shim's buffer handling and
# the HACL calls it issues read/write in bounds and exhibit no UB on real
# key-schedule-shaped and adversarial inputs.
#
# -fwrapv keeps HACL's defined wraparound from tripping UBSan's signed-overflow
# check; ASan leak detection is off because the un-instrumented Lean runtime owns
# allocations ASan cannot account for.
set -eu

cd "$(dirname "$0")/.."
NATIVE="Kroopt/Native"
HACL="$NATIVE/hacl"

# Locate the Lean toolchain (include + runtime libs) from leanc's own flags.
if ! command -v leanc >/dev/null 2>&1; then
  echo "leanc not found on PATH (need elan/Lean toolchain)" >&2; exit 1
fi
LEANINC=$(leanc --print-cflags | tr ' ' '\n' | grep '/include$' | head -1)
TC=$(dirname "$LEANINC")
LEANLIB="$TC/lib/lean"
if [ ! -f "$LEANLIB/libleanshared.so" ]; then
  echo "libleanshared.so not found under $LEANLIB" >&2; exit 1
fi

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
BIN="$OUT/kroopt_sanitizer_harness"

SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -fwrapv"
INC="-I $HACL -I $HACL/internal -I $HACL/include -I $HACL/minimal -I $NATIVE -I $LEANINC"
# HACL sources the shim's exercised primitives depend on (no socket shim).
HACL_SRCS="
  $HACL/Hacl_Curve25519_51.c
  $HACL/Hacl_Chacha20Poly1305_32.c
  $HACL/Hacl_Chacha20.c
  $HACL/Hacl_Poly1305_32.c
  $HACL/Hacl_Hash_SHA2.c
  $HACL/Hacl_Streaming_SHA2.c
  $HACL/Hacl_HKDF.c
  $HACL/Hacl_HMAC.c
  $HACL/Hacl_Ed25519.c
  $HACL/Lib_Memzero0.c"

echo "Compiling shim + HACL + harness under ASan/UBSan (gcc $(gcc -dumpversion))..."
# shellcheck disable=SC2086
gcc -std=c11 -O1 -g $SAN -ffunction-sections -fdata-sections $INC -D_GNU_SOURCE -w \
  "$NATIVE/kroopt_sanitizer_harness.c" "$NATIVE/kroopt_ffi.c" $HACL_SRCS \
  -L "$LEANLIB" -lleanshared -Wl,-rpath,"$LEANLIB" -Wl,--gc-sections \
  -o "$BIN"

echo "Running harness..."
LD_LIBRARY_PATH="$LEANLIB" \
  ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:abort_on_error=1 \
  "$BIN"
