#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"
cd ..

models=(7 8 9 10 11 12 13 14 15 16 17)

for shot in {1..3}; do
    for model_id in "${models[@]}"; do
        echo "Clearing Hugging Face cache before running model_id $model_id, shot $shot..."
        rm -rf $CACHE_PATH

        if [ "$shot" -eq 0 ]; then
            for quantized_random in "yes" "no"; do
                echo "Running shot $shot with quantized_random=$quantized_random..."
                
                python statement_semantic.py \
                    --data_id 10 \
                    --model_id $model_id \
                    --pt_id 1 \
                    --language python \
                    --prediction statement \
                    --shot $shot \
                    --incontext different \
                    --CoT no \
                    --quantized_prediction yes \
                    --API_def no \
                    --quantized_random $quantized_random
            done
        else
            quantized_random="no"
            echo "Running shot $shot with quantized_random=$quantized_random..."
            
            python statement_semantic.py \
                --data_id 10 \
                --model_id $model_id \
                --pt_id 1 \
                --language python \
                --prediction statement \
                --shot $shot \
                --incontext different \
                --CoT no \
                --quantized_prediction yes \
                --API_def no \
                --quantized_random $quantized_random
        fi
    done
done

rm -rf $CACHE_PATH
echo "All experiments completed!"