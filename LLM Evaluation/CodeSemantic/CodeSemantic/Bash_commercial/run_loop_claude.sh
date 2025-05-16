#!/bin/bash

cd ..


for model_id in 20; do
  python statement_semantic.py --data_id 14 --model_id $model_id --pt_id 1 --language python --prediction loop --settings body --shot 3 --incontext different --CoT no --quantized_prediction yes

  python statement_semantic.py --data_id 15 --model_id $model_id --pt_id 1 --language python --prediction loop --settings after --shot 3 --incontext different --CoT no --quantized_prediction yes
done