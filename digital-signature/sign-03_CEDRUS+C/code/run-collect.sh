#!/usr/bin/env bash
set -euo pipefail
workers="${1:-16}"
per_worker="${2:-170}"
mkdir -p experiments/oracle
for ((i=0; i<workers; i++)); do
  first=$((i*per_worker))
  d=$(printf 'experiments/oracle/worker-%02d' "$i")
  mkdir -p "$d"
  ./experiments/collect256f "$first" "$per_worker" "$d" >"$d/stdout.txt" 2>"$d/stderr.txt" &
done
wait
find experiments/oracle -name 'record-*.bin' -type f | sort > experiments/record-manifest.txt
wc -l experiments/record-manifest.txt
cat experiments/oracle/worker-*/summary.tsv | tail -n +2 > experiments/worker-summaries.tsv
