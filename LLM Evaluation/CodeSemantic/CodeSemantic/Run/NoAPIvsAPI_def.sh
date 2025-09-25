#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"
cd ..

for model_id in {7..7}; do
    for api_def in "no" "code"; do
        for shot in 0 1 2; do
            python statement_semantic.py \
                --data_id 0 \
                --model_id $model_id \
                --pt_id 1 \
                --language python \
                --prediction statement \
                --shot $shot \
                --incontext different \
                --CoT no \
                --quantized_prediction no \
                --quantized_random no \
                --API_def $api_def
        done
    done
done

rm -rf $CACHE_PATH
echo "Cleared Hugging Face cache after all runs."