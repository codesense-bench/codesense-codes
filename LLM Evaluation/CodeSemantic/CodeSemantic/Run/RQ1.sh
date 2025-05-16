#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"

for model_id in 7; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH

    for shot in 0; do
        for incontext in "different"; do
            for CoT in "no"; do
                for quantized in "no" "yes"; do
                    python statement_semantic.py \
                        --data_id 10 \
                        --model_id $model_id \
                        --pt_id 1 \
                        --language python \
                        --prediction statement \
                        --shot $shot \
                        --incontext $incontext \
                        --CoT $CoT \
                        --quantized_prediction $quantized
                done
            done
        done
    done
done

    for shot in 3; do
        for incontext in "different"; do
            for CoT in "no"; do
                for quantized in "no" "yes"; do
                    python statement_semantic.py \
                        --data_id 10 \
                        --model_id $model_id \
                        --pt_id 1 \
                        --language python \
                        --prediction statement \
                        --shot $shot \
                        --incontext $incontext \
                        --CoT $CoT \
                        --quantized_prediction $quantized
                done
            done
        done
    done

rm -rf $CACHE_PATH