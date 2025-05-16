#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"

declare -A DATA_SETTINGS=(
    [13]="iteration"
    [14]="body"
    [15]="after"
)

# Running for 0-shot
for model_id in {7..17}; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH

    # for data_id in 13 14 15; do
    #     settings=${DATA_SETTINGS[$data_id]}
    #     python statement_semantic.py \
    #         --data_id $data_id \
    #         --model_id $model_id \
    #         --pt_id 1 \
    #         --language python \
    #         --prediction loop \
    #         --settings $settings \
    #         --shot 0 \
    #         --incontext different \
    #         --CoT no \
    #         --quantized_prediction no
    # done

    # for data_id in 13 14 15; do
    #     settings=${DATA_SETTINGS[$data_id]}
    #     python statement_semantic.py \
    #         --data_id $data_id \
    #         --model_id $model_id \
    #         --pt_id 1 \
    #         --language python \
    #         --prediction loop \
    #         --settings $settings \
    #         --shot 3 \
    #         --incontext different \
    #         --CoT yes \
    #         --quantized_prediction no
    # done

    for data_id in 15; do
        settings=${DATA_SETTINGS[$data_id]}
        python statement_semantic.py \
            --data_id $data_id \
            --model_id $model_id \
            --pt_id 1 \
            --language python \
            --prediction loop \
            --settings $settings \
            --shot 3 \
            --incontext different \
            --CoT no \
            --quantized_prediction no
    done
done

rm -rf $CACHE_PATH