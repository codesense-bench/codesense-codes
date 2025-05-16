#!/bin/bash

BASE_CMD="python statement_semantic.py"

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"
FIXED_PARAMS="--pt_id 4 --language python --shot 3 --incontext same --CoT yes"

for model_id in {9..17}; do
    echo "Clearing Hugging Face cache before running model_id $model_id..."
    rm -rf $CACHE_PATH
    echo "========================================"
    echo "Running experiments for model $model_id"
    echo "========================================"
    
    # Statement prediction (data_id 10)
    echo -e "\n1. Statement predictions (data_id 10):"
    echo "Command 1: $BASE_CMD --data_id 10 $FIXED_PARAMS --model_id $model_id --prediction statement --quantized_prediction no"
    $BASE_CMD --data_id 10 $FIXED_PARAMS --model_id $model_id --prediction statement --quantized_prediction no
    
    echo "Command 2: $BASE_CMD --data_id 10 $FIXED_PARAMS --model_id $model_id --prediction statement --quantized_prediction yes"
    $BASE_CMD --data_id 10 $FIXED_PARAMS --model_id $model_id --prediction statement --quantized_prediction yes
    
    # Output prediction (data_id 11)
    echo -e "\n2. Output predictions (data_id 11):"
    echo "Command 3: $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction output --quantized_prediction no"
    $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction output --quantized_prediction no
    
    echo "Command 4: $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction output --quantized_prediction yes"
    $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction output --quantized_prediction yes
    
    # Input prediction (data_id 11)
    echo -e "\n3. Input predictions (data_id 11):"
    echo "Command 5: $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction input --quantized_prediction no"
    $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction input --quantized_prediction no
    
    echo "Command 6: $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction input --quantized_prediction yes"
    $BASE_CMD --data_id 11 $FIXED_PARAMS --model_id $model_id --prediction input --quantized_prediction yes
    
    echo -e "\nCompleted experiments for model $model_id"
    echo "----------------------------------------"
    sleep 1
done

echo -e "\nAll experiments completed!"
rm -rf $CACHE_PATH