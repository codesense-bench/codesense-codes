import json
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.patheffects as path_effects

# Load data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/statement_Accuracy_Results/statement_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Organize results
model_results = defaultdict(lambda: {
    "quantized": defaultdict(float),
    "non_quantized": defaultdict(float)
})

# List of paid models to exclude
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
}

# Populate results
for entry in data:
    model = entry["Model"]
    quant = "quantized" if entry["quantization"] == "yes" else "non_quantized"
    shot = entry["shot"]
    accuracy = entry["accuracy"]
    model_results[model][quant][shot] = accuracy

# All models present in data
models = list(model_results.keys())

# Filter out paid models
filtered_models = [model for model in models]

# Plotting settings
shots = [0, 1, 2, 3]
colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']

# Plot function
def create_plot(quant_mode, title_suffix, models_to_plot):
    fig, ax = plt.subplots(figsize=(12, 6))
    
    for i, shot in enumerate(shots):
        accuracies = [model_results[model][quant_mode][shot] for model in models_to_plot]
        bars = ax.bar(
            np.arange(len(models_to_plot)) + i * 0.2, accuracies,
            width=0.2, color=colors[i], label=f'Shot {shot}',
            edgecolor='white', linewidth=0.5
        )
    
    if quant_mode == "non_quantized":
        quant_mode = "concrete"

    #ax.set_title(f'{quant_mode.capitalize()} Statement Prediction Accuracy', pad=20)
    ax.set_xticks(np.arange(len(models_to_plot)) + 0.3)
    ax.set_xticklabels(models_to_plot, rotation=45, ha='right')
    ax.set_ylabel('Accuracy')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle=':', alpha=0.7)
    ax.legend(bbox_to_anchor=(1, 1), loc='upper right')
    
    plt.savefig(f'{quant_mode}_models_vs_shots.png', bbox_inches='tight', dpi=300)
    plt.show()

# Generate plots excluding paid models
create_plot("quantized", "Yes", filtered_models)
create_plot("non_quantized", "No", filtered_models)
