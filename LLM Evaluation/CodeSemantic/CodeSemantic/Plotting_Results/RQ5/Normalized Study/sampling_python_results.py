import os
import json
import random
import numpy as np
from collections import defaultdict

# Set random seed for reproducibility
random.seed(42)
np.random.seed(42)

PREDICTION_TYPES = ["input", "output"]  
BASE_DIR = "~/CodeSemantic/CodeSemantic/Detailed_Results"
BASE_DIR = os.path.expanduser(BASE_DIR)
SAMPLE_SIZE = 94
EXPECTED_TOTAL = 308

def process_models(prediction_type="input"):
    results = []
    prediction_dir = os.path.join(BASE_DIR, f"Prediction_{prediction_type}_python")
    
    if not os.path.exists(prediction_dir):
        print(f"Directory not found: {prediction_dir}")
        return results

    for model_dir in os.listdir(prediction_dir):
        model_path = os.path.join(prediction_dir, model_dir)
        if not os.path.isdir(model_path):
            continue
            
        shot_dir = os.path.join(model_path, "Shot_0")
        if not os.path.exists(shot_dir):
            continue
            
        for filename in os.listdir(shot_dir):
            if not filename.endswith(".jsonl"):
                continue
                
            quantize = "yes" if "quantization_yes" in filename else "no"
            parsed_results = []
            
            filepath = os.path.join(shot_dir, filename)
            with open(filepath, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        parsed_results.append(data.get("parsed_result", False))
                    except (json.JSONDecodeError, KeyError) as e:
                        print(f"Error processing line in {filepath}: {e}")
                        continue

            try:
                sampled_results = np.random.choice(parsed_results, size=SAMPLE_SIZE, replace=False)
                accuracy = np.mean(sampled_results)
            except ValueError as e:
                print(f"Sampling error in {filepath}: {e}")
                continue
            
            model = model_dir.replace("Model_", "")
            print(model)
            results.append({
                "Model": model_dir.replace("Model_", ""),
                "Prediction": prediction_type,
                "Prompt": 1,
                "Incontext": "different",
                "CoT": "no",
                "shot": 0,
                "quantization": quantize,
                "accuracy": float(accuracy)
            })
    
    return results

if __name__ == "__main__":
    all_results = []
    
    for prediction_type in PREDICTION_TYPES:
        all_results.extend(process_models(prediction_type))
    
    output_file = "sampled_accuracy_results_python.jsonl"
    with open(output_file, "w") as f:
        for result in all_results:
            f.write(json.dumps(result) + "\n")
    
    print(f"Analysis complete. Results saved to {output_file}")
    print(f"Total records processed: {len(all_results)}")