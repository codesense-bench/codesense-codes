import os
import json
from collections import defaultdict


PREDICTION_TYPES = ["input", "output"]  
BASE_DIR = "~/CodeSemantic/CodeSemantic/Detailed_Results"
BASE_DIR = os.path.expanduser(BASE_DIR)

def get_difficulty(code_length):
    if code_length <= 9:
        return "Small"
    elif 9 < code_length < 17:
        return "Medium"
    else:
        return "Hard"

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
            counts = {
                "Small": {"correct": 0, "total": 0},
                "Medium": {"correct": 0, "total": 0},
                "Hard": {"correct": 0, "total": 0}
            }
            
            filepath = os.path.join(shot_dir, filename)
            with open(filepath, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        code_length = data["original_task"]["code_length"]
                        difficulty = get_difficulty(code_length)
                        
                        counts[difficulty]["total"] += 1
                        if data.get("parsed_result", data.get("parsed_result", False)):  
                            counts[difficulty]["correct"] += 1
                    except (json.JSONDecodeError, KeyError) as e:
                        print(f"Error processing line in {filepath}: {e}")
                        continue
          
            results.append({
                "model_name": model_dir.replace("Model_", ""),
                "prediction_type": prediction_type,
                "quantize": quantize,
                "small_accuracy": counts["Small"]["correct"] / counts["Small"]["total"] if counts["Small"]["total"] > 0 else 0,
                "medium_accuracy": counts["Medium"]["correct"] / counts["Medium"]["total"] if counts["Medium"]["total"] > 0 else 0,
                "long_accuracy": counts["Hard"]["correct"] / counts["Hard"]["total"] if counts["Hard"]["total"] > 0 else 0,
                "counts": counts
            })
    
    return results

if __name__ == "__main__":
    all_results = []
    

    for prediction_type in PREDICTION_TYPES:
        all_results.extend(process_models(prediction_type))
    
    output_file = "model_accuracy_analysis.jsonl"
    with open(output_file, "w") as f:
        for result in all_results:
            f.write(json.dumps(result) + "\n")
    
    print(f"Analysis complete. Results saved to {output_file}")
    print(f"Total records processed: {len(all_results)}")