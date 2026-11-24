#!/bin/sh
set -eu

base=/home/mmat/mmat-preview/runs/ngcc-kem-05-ds01/run/slots/c9900576bfd648cb/experiments
stock=$base/optimization128/bike_kem_ml/src/decode/mlthre_model.c
supplied=$base/optimization128_l1json/bike_kem_ml/src/decode/mlthre_model.c
inc_stock=$base/optimization128/bike_kem_ml/include
inc_supplied=$base/optimization128_l1json/bike_kem_ml/include
src_decode=$base/optimization128/bike_kem_ml/src/decode

gcc -O2 -std=c99 -I"$inc_stock" -I"$inc_stock/internal" \
  -Dmlthre_model_predict_delta=stock_predict -c "$stock" -o stock_model.o
gcc -O2 -std=c99 -I"$inc_supplied" -I"$inc_supplied/internal" \
  -Dmlthre_model_predict_delta=l1json_predict -c "$supplied" -o supplied_model.o
gcc -O2 -std=c99 -I"$inc_stock" -I"$inc_stock/internal" \
  model_policy_compare.c stock_model.o supplied_model.o -o model_policy_compare
