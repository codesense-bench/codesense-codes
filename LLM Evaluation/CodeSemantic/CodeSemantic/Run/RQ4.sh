#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"

for model_id in {7..17}; do
  echo "Clearing Hugging Face cache before running model_id $model_id..."
  rm -rf $CACHE_PATH

  for shot in 3; do
    if [ "$shot" -eq 0 ]; then
      python statement_semantic.py \
        --data_id 0 \
        --model_id $model_id \
        --pt_id 0 \
        --language python \
        --prediction statement \
        --shot 0 \
        --incontext different \
        --CoT no
    else
      for incontext in "same" "different"; do
        for CoT in "yes" "no"; do
          python statement_semantic.py \
            --data_id 0 \
            --model_id $model_id \
            --pt_id 0 \
            --language python \
            --prediction statement \
            --shot $shot \
            --incontext $incontext \
            --CoT $CoT
        done
      done
    fi
  done
done

rm -rf $CACHE_PATH