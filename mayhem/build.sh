#!/usr/bin/env bash
#
# mayhem/build.sh — builds the OpenPBS parser/codec libraries (sanitized, for the fuzz harnesses; plain, for
# the selftest oracle), every fuzz harness and its -standalone reproducer, and the selftest binary.
#
# Runs offline inside the commit image as `mayhem` in /mayhem, and is safe to re-run on a `git clean -ffdX` tree.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"
HARNESSES="fuzz_dis_request fuzz_select_spec fuzz_execvnode_seq fuzz_attr_decode fuzz_cli_parse"

# upstream's generated build system (configure and friends are all gitignored)
./autogen.sh

# configure_tree <dir>: out-of-tree configure; the per-build flags are given to make, not configure
configure_tree() {
  rm -rf "$1"
  mkdir -p "$1"
  (cd "$1" && env -u CFLAGS -u LDFLAGS CC="$CC" CFLAGS="-O1" "$SRC/configure" --disable-shared >configure.log 2>&1) \
    || { tail -n 40 "$1/configure.log"; exit 1; }
}

# build_libs <dir> <cflags>: only the three libraries the targets need (the full tree needs python and a database)
build_libs() {
  make -C "$1/src/include" -j"$MAYHEM_JOBS" >"$1/make-include.log" 2>&1 || { tail -n 40 "$1/make-include.log"; exit 1; }
  for lib in Libpbs Liblog Libutil; do
    make -C "$1/src/lib/$lib" -j"$MAYHEM_JOBS" CFLAGS="$2" >"$1/make-$lib.log" 2>&1 \
      || { tail -n 40 "$1/make-$lib.log"; exit 1; }
  done
}

# server-side request decoders the DIS harness and the selftest link in; section GC drops the rest of the server
server_objs() {
  local dir="$1" cflags="$2"
  for f in dis_read process_request; do
    $CC $cflags -ffunction-sections -fdata-sections -I"$SRC/src/include" -I"$dir/src/include" \
      -c "$SRC/src/server/$f.c" -o "$dir/$f.o"
  done
}

# --gc-sections drops the unused rest of the server TU; start-stop-gc stops the SanCov __start_ symbols keeping it alive.
libs_of() {
  echo "$1/src/lib/Libpbs/.libs/libpbs.a $1/src/lib/Libutil/libutil.a $1/src/lib/Liblog/liblog.a $1/src/lib/Libpbs/.libs/libpbs.a -lcrypto -lpthread -lz -lm"
}

# ---- sanitized build (fuzz targets) ----
FB="$M/build-fuzz"
FCFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1"
configure_tree "$FB"
build_libs "$FB" "$FCFLAGS"
server_objs "$FB" "$FCFLAGS"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$FB/lsan_off.o"

for h in $HARNESSES; do
  extra=""
  [ "$h" = fuzz_dis_request ] && extra="$FB/dis_read.o $FB/process_request.o"
  $CC $FCFLAGS -I"$SRC/src/include" -I"$FB/src/include" -c "$M/$h.c" -o "$FB/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FB/$h.o" $extra "$FB/lsan_off.o" $(libs_of "$FB") \
    -Wl,--gc-sections -Wl,-z,start-stop-gc -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "$FB/$h.o" $extra "$FB/lsan_off.o" $(libs_of "$FB") \
    -Wl,--gc-sections -Wl,-z,start-stop-gc -o "$SRC/$h-standalone"
done

# ---- normal-flags build (selftest oracle) ----
TB="$M/build-test"
TCFLAGS="-O1 $COVERAGE_FLAGS"
configure_tree "$TB"
build_libs "$TB" "$TCFLAGS"
server_objs "$TB" "$TCFLAGS"
$CC $TCFLAGS -I"$SRC/src/include" -I"$TB/src/include" "$M/selftest.c" "$TB/dis_read.o" "$TB/process_request.o" \
  $(libs_of "$TB") $COVERAGE_FLAGS -Wl,--gc-sections -Wl,-z,start-stop-gc -o "$TB/selftest"
