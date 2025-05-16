#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"

for model_id in {7..17}; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH

    python statement_semantic.py --data_id 16 --model_id $model_id --pt_id 0 --language c --prediction output --shot 0 --incontext different --CoT no --quantized_prediction no
    python statement_semantic.py --data_id 16 --model_id $model_id --pt_id 0 --language c --prediction input --shot 0 --incontext different --CoT no --quantized_prediction no
    
    python statement_semantic.py --data_id 17 --model_id $model_id --pt_id 0 --language java --prediction output --shot 0 --incontext different --CoT no --quantized_prediction no
    python statement_semantic.py --data_id 17 --model_id $model_id --pt_id 0 --language java --prediction input --shot 0 --incontext different --CoT no --quantized_prediction no
done

for model_id in {7..17}; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH

    for shot in 0; do
        for incontext in "different"; do
            for CoT in "no"; do
                for prediction in "output" "input";do
                    for quantized in "no"; do
                        python statement_semantic.py \
                            --data_id 11 \
                            --model_id $model_id \
                            --pt_id 1 \
                            --language python \
                            --prediction $prediction\
                            --shot $shot \
                            --incontext $incontext \
                            --CoT $CoT \
                            --quantized_prediction $quantized
                    done
                done
            done
        done
    done
done

rm -rf $CACHE_PATH