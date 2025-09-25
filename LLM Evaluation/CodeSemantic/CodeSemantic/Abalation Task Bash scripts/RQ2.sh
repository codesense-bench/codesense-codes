#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"
cd ..

for model_id in {7..17}; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH

    for pt_id in 5 6 7; do
        python statement_semantic.py \
            --data_id 0 \
            --model_id $model_id \
            --pt_id $pt_id \
            --language python \
            --prediction statement \
            --shot 3 \
            --incontext different \
            --CoT no \
            --quantized_prediction no
    done
done

rm -rf $CACHE_PATH