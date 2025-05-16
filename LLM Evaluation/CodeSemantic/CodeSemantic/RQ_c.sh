#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"

for model_id in 9 11; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH

    #python statement_semantic.py --data_id 18 --model_id $model_id --pt_id 1 --language python --prediction conditional --shot 0 --incontext different --CoT no --quantized_prediction no
    python statement_semantic.py --data_id 9 --model_id $model_id --pt_id 0 --language c --prediction alias --shot 0 --incontext different --CoT no --quantized_prediction no
    # python statement_semantic.py --data_id 3 --model_id $model_id --pt_id 1 --language c --prediction block --shot 0 --incontext different --CoT no --quantized_prediction no
    # python statement_semantic.py --data_id 1 --model_id $model_id --pt_id 1 --language c --prediction statement --shot 0 --incontext different --CoT no --quantized_prediction no
done

rm -rf $CACHE_PATH