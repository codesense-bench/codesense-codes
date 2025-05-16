#!/bin/bash

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"

echo "Starting experiment - initial cache clearing..."
rm -rf "$CACHE_PATH"

for model_id in {7..17}; do
    echo "Processing model $model_id..."
    
    for quantized in yes no; do
        echo "  Running with quantized_prediction=$quantized"
        
        python statement_semantic.py \
            --data_id 12 \
            --model_id "$model_id" \
            --pt_id 0 \
            --language python \
            --prediction block \
            --shot 3 \
            --incontext same \
            --CoT yes \
            --quantized_prediction "$quantized"
            
        sleep 1
    done
    echo "  Clearing cache after model $model_id..."
    rm -rf "$CACHE_PATH"
done

echo "All experiments completed successfully."