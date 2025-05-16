import json
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

try:
    with open('/home/XXX/CodeSemantic/CodeSemantic/result_quantize.jsonl', 'r') as f:
        data = [json.loads(line) for line in f]
    print(f"Loaded {len(data)} entries")
except Exception as e:
    print(f"Error loading file: {e}")
    exit()

print("\nFirst entry sample:")
print(data[0])


shot_accuracies = defaultdict(list)
quant_no_entries = 0

for entry in data:
    if str(entry.get('quantization', '')).lower() == 'yes':
        quant_no_entries += 1
        try:
            shots = entry['shot']
            accuracy = entry['accuracy']
            shot_accuracies[shots].append(accuracy)
        except KeyError as e:
            print(f"Missing key in entry: {e}")

print(f"\nFound {quant_no_entries} entries with quantization='no'")
print("Shots found:", sorted(shot_accuracies.keys()))


if not shot_accuracies:
    print("No data to plot - check your filtering condition")
    exit()

shots = sorted(shot_accuracies.keys())
avg_accuracies = [np.mean(shot_accuracies[shot]) for shot in shots]

print("\nAverage accuracies per shot:")
for shot, acc in zip(shots, avg_accuracies):
    print(f"Shot {shot}: {acc:.3f}")


plt.figure(figsize=(10, 6))
plt.plot(shots, avg_accuracies, 
         marker='o', 
         linestyle='-', 
         linewidth=2, 
         markersize=10,
         color='royalblue')

plt.xlabel('Number of Shots', fontsize=12)
plt.ylabel('Average Accuracy', fontsize=12)
plt.title('Average Shot Accuracy (Quantization Yes)', fontsize=14, pad=20)
plt.xticks(shots)
plt.grid(True, linestyle='--', alpha=0.5)
plt.ylim(0, 1.05)  


for x, y in zip(shots, avg_accuracies):
    plt.text(x, y+0.02, f'{y:.3f}', ha='center', va='bottom')

plt.tight_layout()


plt.savefig('average_shot_accuracy_quantized.png', dpi=300, bbox_inches='tight')
print("\nPlot saved as 'average_shot_accuracy.png'")
plt.show()