#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"
cd ..

for model_id in {7..17}; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH

    # python statement_semantic.py \
    #     --data_id 29 \
    #     --model_id $model_id \
    #     --pt_id 1 \
    #     --language python \
    #     --prediction statement \
    #     --shot 1 \
    #     --incontext same \
    #     --CoT no \
    #     --quantized_prediction no \
    #     --quantized_random no \
    #     --API_def no

    python statement_semantic.py \
        --data_id 29 \
        --model_id $model_id \
        --pt_id 1 \
        --language python \
        --prediction statement \
        --shot 0 \
        --incontext different \
        --CoT no \
        --quantized_prediction no \
        --quantized_random no \
        --API_def code
done

rm -rf $CACHE_PATH