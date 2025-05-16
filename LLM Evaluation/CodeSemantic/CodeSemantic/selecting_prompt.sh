#!/bin/bash

BASE_CMD="python statement_semantic.py"

LANGUAGE="python"
INCONTEXT="different"
COT="no"

CACHE_PATH="/home/XXX/.cache/huggingface/hub/*"

for MODEL_ID in {7..9}; do
    echo "Clearing Cache"
    rm -rf $CACHE_PATH
    for PT_ID in {0..4}; do
        for SHOT in {0..3}; do
            # --- Non-quantized predictions ---
            # $BASE_CMD --data_id 10 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction statement --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction no
            # $BASE_CMD --data_id 11 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction input --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction no
            # $BASE_CMD --data_id 11 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction output --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction no
            # $BASE_CMD --data_id 12 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction block --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction no

            #if [ $SHOT -ne 0 ]; then
            $BASE_CMD --data_id 10 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction statement --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction yes
            #$BASE_CMD --data_id 11 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction input --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction yes
            $BASE_CMD --data_id 11 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction output --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction yes
            #$BASE_CMD --data_id 12 --model_id $MODEL_ID --pt_id $PT_ID --language $LANGUAGE --prediction block --shot $SHOT --incontext $INCONTEXT --CoT $COT --quantized_prediction yes
            #fi
        done
    done
done