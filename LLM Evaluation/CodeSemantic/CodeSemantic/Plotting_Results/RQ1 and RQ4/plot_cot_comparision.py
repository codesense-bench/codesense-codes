import json
from collections import defaultdict
import matplotlib.pyplot as plt
import numpy as np

# Define reasoning models
REASONING_MODELS = {
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "granite-3.2-8b-instruct",
    "granite-3.2-8b-instruct-preview",
}

# Load and process data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/statement_Accuracy_Results/statement_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

model_results = defaultdict(lambda: {
    "quantized": {
        "cot_yes": defaultdict(float),
        "cot_no": defaultdict(float)
    },
    "non_quantized": {
        "cot_yes": defaultdict(float),
        "cot_no": defaultdict(float)
    }
})

for entry in data:
    if entry["Incontext"] != "same":  
        continue
        
    model = entry["Model"]
    quant = "quantized" if entry["quantization"] == "yes" else "non_quantized"
    cot = "cot_yes" if entry["CoT"] == "yes" else "cot_no"
    shot = entry["shot"]
    accuracy = entry["accuracy"]
    
    model_results[model][quant][cot][shot] = accuracy

# Sort models: non-reasoning first (False comes before True in sorting)
models = sorted(model_results.keys(), key=lambda x: x in REASONING_MODELS)

def create_cot_comparison_plot(quant_mode):
    # Professional color palette
    colors = {
        'cot_yes': '#009E73', 
        'cot_no': '#D55E00' 
    }
    fig, ax = plt.subplots(figsize=(12, 6))
    
    shot = 3 
    
    cot_yes_accuracies = [model_results[model][quant_mode]["cot_yes"][shot] for model in models]
    cot_no_accuracies = [model_results[model][quant_mode]["cot_no"][shot] for model in models]
    
    x = np.arange(len(models))
    width = 0.35
    
    # Plot bars with reasoning model indicators
    for i, model in enumerate(models):
        is_reasoning = model in REASONING_MODELS
        edgecolor = 'red' if is_reasoning else 'black'
        hatch = '///' if is_reasoning else None
        
        ax.bar(x[i] - width/2, cot_yes_accuracies[i], width, 
              color=colors['cot_yes'], edgecolor=edgecolor, hatch=hatch)
        ax.bar(x[i] + width/2, cot_no_accuracies[i], width, 
              color=colors['cot_no'], edgecolor=edgecolor, hatch=hatch)
    
    display_mode = "Quantized" if quant_mode == "quantized" else "Concrete"
    
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right')
    ax.set_ylabel('Accuracy')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle=':', alpha=0.7)
    
    # Create custom legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=colors['cot_yes'], label='CoT: Yes'),
        Patch(facecolor=colors['cot_no'], label='CoT: No'),
        Patch(facecolor='white', edgecolor='red', hatch='///', label='Reasoning Model'),
        Patch(facecolor='white', edgecolor='black', label='Non-Reasoning Model')
    ]
    ax.legend(handles=legend_elements, bbox_to_anchor=(1, 1), loc='upper right')
    
    plt.tight_layout()
    plt.savefig(f'{display_mode}_COT_comparison.png', bbox_inches='tight', dpi=300)
    plt.show()
    
def create_quantization_comparison_plot():
    # Professional color palette
    colors = {
        'cot_yes': '#008000',  # Green for CoT: Yes
        'cot_no': '#FF0000',   # Red for CoT: No
        'quantized': '#1f77b4',  # Blue for Quantized models
        'non_quantized': '#ff7f0e'  # Orange for Non-Quantized models
    }
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    shot = 3
    cot = "cot_yes"
    
    quantized_accuracies = [model_results[model]["quantized"][cot][shot] for model in models]
    concrete_accuracies = [model_results[model]["non_quantized"][cot][shot] for model in models]
    
    x = np.arange(len(models))
    width = 0.35
    
    # Plot bars with reasoning model indicators
    for i, model in enumerate(models):
        is_reasoning = model in REASONING_MODELS
        edgecolor = 'red' if is_reasoning else 'black'
        hatch = '///' if is_reasoning else None
        
        ax.bar(x[i] - width/2, quantized_accuracies[i], width, 
              color=colors['quantized'], edgecolor=edgecolor, hatch=hatch)
        ax.bar(x[i] + width/2, concrete_accuracies[i], width, 
              color=colors['non_quantized'], edgecolor=edgecolor, hatch=hatch)
    
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right')
    ax.set_ylabel('Accuracy')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle=':', alpha=0.7)
    
    # Create custom legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=colors['quantized'], label='Quantized'),
        Patch(facecolor=colors['non_quantized'], label='Non-Quantized'),
        Patch(facecolor='white', edgecolor='red', hatch='///', label='Reasoning Model'),
        Patch(facecolor='white', edgecolor='black', label='Non-Reasoning Model')
    ]
    ax.legend(handles=legend_elements, bbox_to_anchor=(1, 1), loc='upper right')
    
    plt.tight_layout()
    plt.savefig('Quantized_vs_Concrete_CoT_Yes_comparison.png', bbox_inches='tight', dpi=300)
    plt.show()

# Create and save plots
create_quantization_comparison_plot()
create_cot_comparison_plot("quantized")
create_cot_comparison_plot("non_quantized")
