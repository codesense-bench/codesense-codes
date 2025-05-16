#!/bin/bash

cd ..

# model_ids=(20)

# for model_id in "${model_ids[@]}"; do

#   # python statement_semantic.py --data_id 22 --model_id $model_id --pt_id 1 --language python --prediction block --shot 0 --incontext different --CoT no --quantized_prediction no
  
#   # python statement_semantic.py --data_id 23 --model_id $model_id --pt_id 1 --language c --prediction block --shot 0 --incontext different --CoT no --quantized_prediction no

#   # python statement_semantic.py --data_id 18 --model_id $model_id --pt_id 1 --language python --prediction conditional --shot 0 --incontext different --CoT no --quantized_prediction no

#   # python statement_semantic.py --data_id 13 --model_id $model_id --pt_id 1 --language python --prediction loop --settings iteration --shot 3 --incontext different --CoT no --quantized_prediction no

#   # python statement_semantic.py --data_id 14 --model_id $model_id --pt_id 1 --language python --prediction loop --settings body --shot 3 --incontext different --CoT no --quantized_prediction no

#   python statement_semantic.py --data_id 15 --model_id $model_id --pt_id 1 --language python --prediction loop --settings after --shot 3 --incontext different --CoT yes --quantized_prediction no

# done



# python statement_semantic.py --data_id 19 --model_id 20 --pt_id 1 --language python --prediction statement --shot 0 --incontext different --CoT no --quantized_prediction no
# python statement_semantic.py --data_id 20 --model_id 20 --pt_id 1  --language python --prediction output --shot 0 --incontext different --CoT no --quantized_prediction no
# python statement_semantic.py --data_id 20 --model_id 20 --pt_id 1  --language python --prediction input --shot 0 --incontext different --CoT no --quantized_prediction no

# python statement_semantic.py --data_id 16 --model_id 20 --pt_id 1 --language c --prediction output --shot 0 --incontext different --CoT no --quantized_prediction no
# python statement_semantic.py --data_id 16 --model_id 20 --pt_id 1 --language c --prediction input --shot 0 --incontext different --CoT no --quantized_prediction no

# python statement_semantic.py --data_id 17 --model_id 20 --pt_id 1 --language java --prediction output --shot 0 --incontext different --CoT no --quantized_prediction no
# python statement_semantic.py --data_id 17 --model_id 20 --pt_id 1 --language java --prediction input --shot 0 --incontext different --CoT no --quantized_prediction no

# python statement_semantic.py --data_id 9 --model_id 20 --pt_id 1 --language c --prediction alias --shot 0 --incontext different --CoT no --quantized_prediction no


# python statement_semantic.py --data_id 13 --model_id 20 --pt_id 1 --language python --prediction loop --settings iteration --shot 0 --incontext different --CoT no --quantized_prediction no
# python statement_semantic.py --data_id 14 --model_id 20 --pt_id 1 --language python --prediction loop --settings body --shot 0 --incontext different --CoT no --quantized_prediction no
# python statement_semantic.py --data_id 15 --model_id 20 --pt_id 1 --language python --prediction loop --settings after --shot 0 --incontext different --CoT no --quantized_prediction no


# python statement_semantic.py --data_id 21 --model_id 20 --pt_id 1 --language c --prediction statement --shot 0 --incontext different --CoT no --quantized_prediction no

for model_id in 0; do
    for shot in 1 2 3; do
        for incontext in "different" "same"; do
            for CoT in "no" "yes"; do
                for quantized in "yes" "no"; do
                    python statement_semantic.py \
                        --data_id 19 \
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
