#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
original="$root/original_160f"
corrected="$root/spec_160f"

field_for_sample() {
  local file=$1
  local sample=$2
  local field=$3
  awk -v n="$sample" -v key="$field" '
    $1 == "Count" { count = $3; next }
    count == n && $1 == key { print $3; exit }
  ' "$file"
}

check() {
  local label=$1
  local verifier=$2
  local pk=$3
  local signature=$4
  local message=$5
  local expected=$6
  local result
  if "$verifier" "$pk" "$signature" "$message"; then
    result=ACCEPT
  else
    result=REJECT
  fi
  printf 'sample=%s check=%s result=%s\n' "$sample" "$label" "$result"
  if [[ "$result" != "$expected" ]]; then
    printf 'unexpected result for sample=%s check=%s: got %s, expected %s\n' \
      "$sample" "$label" "$result" "$expected" >&2
    return 1
  fi
}

for sample in $(seq 0 9); do
  original_kat="$original/output/KAT_SIG_Lynxer-160f.txt"
  corrected_kat="$corrected/output/KAT_SIG_Lynxer-160f.txt"
  pk_original=$(field_for_sample "$original_kat" "$sample" PK)
  sn_original=$(field_for_sample "$original_kat" "$sample" Sn)
  msg_original=$(field_for_sample "$original_kat" "$sample" M)
  pk_corrected=$(field_for_sample "$corrected_kat" "$sample" PK)
  sn_corrected=$(field_for_sample "$corrected_kat" "$sample" Sn)
  msg_corrected=$(field_for_sample "$corrected_kat" "$sample" M)

  check original_over_original "$original/verify_hex" \
    "$pk_original" "$sn_original" "$msg_original" ACCEPT
  check corrected_over_original "$corrected/verify_hex" \
    "$pk_original" "$sn_original" "$msg_original" REJECT
  check corrected_over_corrected "$corrected/verify_hex" \
    "$pk_corrected" "$sn_corrected" "$msg_corrected" ACCEPT
  check original_over_corrected "$original/verify_hex" \
    "$pk_corrected" "$sn_corrected" "$msg_corrected" REJECT
done

printf 'summary samples=10 checks_per_sample=4 result=ALL_EXPECTED\n'
