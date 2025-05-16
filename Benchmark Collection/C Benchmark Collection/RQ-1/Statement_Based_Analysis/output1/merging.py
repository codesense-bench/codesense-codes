import json
from pathlib import Path

input_dir = Path(".")  
output_file = "statement_prediction_dataset_C.jsonl"

priority_files = [
    "Constant Assignment.jsonl",
    "Assignment.jsonl",
    "Arithmetic Assignment.jsonl",
    "Branch.jsonl",
    "Function Call.jsonl"
]

merged_data = []
current_idx = 0

for filename in priority_files:
    filepath = input_dir / filename
    if not filepath.exists():
        print(f"Warning: {filename} not found - skipping")
        continue
        
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                merged_data.append({
                    "idx": current_idx,
                    **{k:v for k,v in data.items() if k != "idx"}
                })
                current_idx += 1
            except json.JSONDecodeError as e:
                print(f"Skipping malformed line in {filename}: {e}")

# Write merged data
with open(output_file, 'w', encoding='utf-8') as f:
    for item in merged_data:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

print(f"\nSuccessfully merged {len(merged_data)} entries")
print(f"Output file: {output_file}")