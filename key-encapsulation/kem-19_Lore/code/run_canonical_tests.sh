#!/usr/bin/env bash
set -u

root="$(cd "$(dirname "$0")" && pwd)"
ref="$root/work/Lore/Reference implementation/ref"
harness="$root/harness/canonical_harness.c"
build="$root/work/build"
logs="$root/build-logs"
expected_commit="9321cf3597def00cb1f74d5e569cef1a6ca00d39"

mkdir -p "$build" "$logs"
actual_commit="$(git -C "$root/work/Lore" rev-parse HEAD)"
if [[ "$actual_commit" != "$expected_commit" ]]; then
    printf 'unexpected Lore commit: %s\n' "$actual_commit" >&2
    exit 2
fi

make -C "$ref" -j4 test kat >"$logs/make.log" 2>&1
make_status=$?
if [[ $make_status -ne 0 ]]; then
    printf 'build failed; see %s\n' "$logs/make.log" >&2
    exit $make_status
fi

srcdir="$ref"
sources=(
    kem.c pke.c indcpa.c polyvec.c poly.c ntt.c sampler.c reduce.c
    symmetric-shake.c fips202.c toomcook.c verify.c bch_codec.c randombytes.c
)

for level in 1 2 3 4; do
    (
        cd "$srcdir" || exit
        gcc -O2 -DLORE_LEVEL="$level" -I. "$harness" "${sources[@]}" \
            -o "$build/canonical_plain_$level"
    ) >"$logs/compile-plain-$level.log" 2>&1 || exit
    "$build/canonical_plain_$level" derand >"$logs/plain-derand-$level.log" 2>&1
    printf 'exit=%s\n' "$?" >>"$logs/plain-derand-$level.log"
    "$build/canonical_plain_$level" random >"$logs/plain-random-$level.log" 2>&1
    printf 'exit=%s\n' "$?" >>"$logs/plain-random-$level.log"
    "$build/canonical_plain_$level" guardcoins >"$logs/guardcoins-$level.log" 2>&1
    printf 'exit=%s\n' "$?" >>"$logs/guardcoins-$level.log"
done

for level in 1 2 3 4; do
    (
        cd "$srcdir" || exit
        gcc -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
            -DLORE_LEVEL="$level" -I. "$harness" "${sources[@]}" \
            -o "$build/canonical_asan_$level"
    ) >"$logs/compile-asan-$level.log" 2>&1 || exit
    ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 \
        "$build/canonical_asan_$level" derand >"$logs/asan-derand-$level.log" 2>&1
    printf 'asan-derand level %s exit=%s\n' "$level" "$?"
done

for level in 1 2 3 4; do
    (cd "$srcdir" && "./PQCgenKAT_pke_$level") >"$logs/kat-$level.log" 2>&1
    printf 'kat level %s exit=%s\n' "$level" "$?"
done
