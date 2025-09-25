#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"
cd ..

for data_id in {24..27}; do
    echo "Clearing Hugging Face cache before running data_id $data_id..."
    rm -rf $CACHE_PATH

    python statement_semantic.py \
        --data_id $data_id \
        --model_id 14 \
        --pt_id 1 \
        --language python \
        --prediction loop \
        --settings iteration \
        --shot 0 \
        --incontext different \
        --CoT no \
        --quantized_prediction no\
        --quantized_random no
done

rm -rf $CACHE_PATH
