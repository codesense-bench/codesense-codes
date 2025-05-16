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
        
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
}

# Reorganize data structure
model_results = defaultdict(lambda: {
    "quantized": {
        "same": defaultdict(float),
        "different": defaultdict(float)
    },
    "non_quantized": {
        "same": defaultdict(float),
        "different": defaultdict(float)
    }
})

# Populate results
for entry in data:
    model = entry["Model"]
    quant = "quantized" if entry["quantization"] == "yes" else "non_quantized"
    incontext = entry["Incontext"]  
    shot = entry["shot"]
    accuracy = entry["accuracy"]
    
    model_results[model][quant][incontext][shot] = accuracy

# All models present in data
all_models = list(model_results.keys())

# List of paid models to exclude
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
}

# Filter out paid models
models = [model for model in all_models if model not in PAID_MODELS]

# Color settings
colors = {'same': '#1f77b4', 'different': '#ff7f0e'}  

# Plot function
def create_incontext_comparison_plot(quant_mode):
    fig, ax = plt.subplots(figsize=(12, 6))
    
    shot = 3  # Only shot=3 is being plotted
    
    # Get accuracies for filtered models
    same_accuracies = [model_results[model][quant_mode]["same"][shot] for model in models]
    different_accuracies = [model_results[model][quant_mode]["different"][shot] for model in models]
    
    x = np.arange(len(models))
    width = 0.35
    
    # Plot bars
    bars_same = ax.bar(x - width/2, same_accuracies, width, 
                      label='Incontext: Same', color=colors['same'],
                      edgecolor='white', linewidth=0.5)
    bars_diff = ax.bar(x + width/2, different_accuracies, width, 
                      label='Incontext: Different', color=colors['different'],
                      edgecolor='white', linewidth=0.5)
    
    # Title formatting
    display_mode = "Concrete" if quant_mode == "non_quantized" else "Quantized"
    
    # Axes and legend
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right')
    ax.set_ylabel('Accuracy')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle=':', alpha=0.7)
    ax.legend(bbox_to_anchor=(1, 1), loc='upper right')
    
    plt.tight_layout()
    plt.savefig(f'{display_mode}_value_incontext_comparison.png', bbox_inches='tight', dpi=300)
    plt.show()

# Generate plots excluding paid models
create_incontext_comparison_plot("quantized")
create_incontext_comparison_plot("non_quantized")
