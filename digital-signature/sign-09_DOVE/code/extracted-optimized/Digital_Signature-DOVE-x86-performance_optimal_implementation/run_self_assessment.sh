#!/bin/sh
# DOVE digital-signature self-assessment (Reference + Optimized).
#
# Layout:
#   API_PKC/Implementations/Reference_Implementation/DOVE_{classic,pkc_skc}_ref
#   API_PKC/Implementations/Optimized_Implementation/DOVE_{classic,pkc_skc}_avx2
#
# Builds 6 benchmarks per implementation (2 variants × 3 levels: 128/256/512).
# Only measures keygen / sign / verify (ngcc_bench). Does NOT run KAT generation.
#
# Usage:
#   ./run_self_assessment.sh [iterations] [reference|optimized|all]
set -e

ITERS="${1:-100}"
WHICH="${2:-all}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/build"
LOG="$HERE/logs/self_assessment.log"

discover_bench_folders() {
    _root="$1"
    _suffix="$2"
    _found=""
    for _dir in "$_root"/DOVE_*_"$_suffix"; do
        [ -d "$_dir" ] || continue
        _base=$(basename "$_dir")
        _base="${_base%_${_suffix}}"
        for _level in 128 256 512; do
            _found="${_found}${_base}_${_level}
"
        done
    done
    printf '%s' "$_found" | sed '/^$/d' | sort -t_ -k3 -n
}

run_impl() {
    _label="$1"
    _pkc_flag="$2"
    _suffix="$3"
    _impl_dir="$4"
    _reports="$HERE/reports_${_label}"
    _build="$BUILD/${_label}"

    echo ""
    echo "=========================================="
    echo "== Self-assessment: ${_label} (keygen/sign/verify × ${ITERS}, no KAT) =="
    echo "=========================================="

    mkdir -p "$_reports" "$HERE/logs"
    rm -f "$_reports"/*.json "$_reports/summary.csv"

    echo "== Building cmake (${_label}) =="
    mkdir -p "$_build"
    cmake -S "$HERE" -B "$_build" -DPKC_OPTIMIZED_IMPL="${_pkc_flag}" -DPKC_BUILD_KAT=OFF >/dev/null
    make -C "$_build" -j$(nproc 2>/dev/null || echo 2) ngcc_bench 2>&1 | grep -E '^make.*Error|error:' || true

    _root="$HERE/API_PKC/Implementations/${_impl_dir}"
    discover_bench_folders "$_root" "$_suffix" | while IFS= read -r FOLDER; do
        [ -n "$FOLDER" ] || continue
        LEVEL="${FOLDER##*_}"
        FAMILY="${FOLDER%_*}"
        FAMILY_LC=$(printf '%s' "$FAMILY" | tr '[:upper:]' '[:lower:]')
        CLI="${FAMILY_LC}-${LEVEL}"
        echo "== Benchmark ${FOLDER} =="
        "$_build/ngcc_bench_${FOLDER}" -a "$CLI" -t "$ITERS" \
            -l "$_build/API_PKC/Implementations/${_impl_dir}/libsigalg_${FOLDER}.a" \
            -o "$_reports" 2>&1 | tee -a "$LOG"
    done

    echo "== Report (${_label}) =="
    if command -v python3 >/dev/null 2>&1; then
        IMPL_LABEL="$_label" python3 "$HERE/gen_report.py" \
            --reports "$_reports" \
            --out "$HERE/self_assessment_report_${_label}.md"
    else
        echo "WARN: python3 not found; skip report for ${_label}."
    fi

    echo "== Summary (${_label}): $_reports/summary.csv =="
    cat "$_reports/summary.csv" 2>/dev/null || true
}

mkdir -p "$HERE/logs"
: > "$LOG"

case "$WHICH" in
reference|ref|Reference|REF)
    run_impl reference OFF ref Reference_Implementation
    ;;
optimized|opt|Optimized|OPT)
    run_impl optimized ON avx2 Optimized_Implementation
    ;;
all|"")
    run_impl reference OFF ref Reference_Implementation
    run_impl optimized ON avx2 Optimized_Implementation
    ;;
*)
    echo "Unknown mode: $WHICH (use reference, optimized, or all)" >&2
    exit 1
    ;;
esac

echo ""
echo "== Done. Reports: =="
ls -1 "$HERE"/self_assessment_report_*.md 2>/dev/null || true
