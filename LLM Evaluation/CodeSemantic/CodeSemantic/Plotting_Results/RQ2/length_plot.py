import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# Define reasoning models
REASONING_MODELS = {
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "granite-3.2-8b-instruct",
    "granite-3.2-8b-instruct-preview",
}

def plot_quantization_accuracy(data, prediction_type, quantize_type):
    """
    Generate accuracy plot with non-reasoning models first, then reasoning models
    
    Parameters:
    - data: List of dictionaries containing the data
    - prediction_type: "input" or "output"
    - quantize_type: "yes" or "no"
    """
    # Filter relevant records
    records = []
    for entry in data:
        if (entry["prediction_type"] == prediction_type and 
            entry["quantize"] == quantize_type):
            records.append({
                "Model": entry["model_name"],
                "Small": entry["small_accuracy"],
                "Medium": entry["medium_accuracy"],
                "Long": entry["long_accuracy"],
                "IsReasoning": entry["model_name"] in REASONING_MODELS
            })
    
    if not records: 
        print(f"No data for {prediction_type} prediction with quantize={quantize_type}")
        return
    
    df = pd.DataFrame(records)
    
    # Explicitly separate and sort models
    all_models = df['Model'].unique()
    print(all_models)
    non_reasoning = sorted([m for m in all_models if m not in REASONING_MODELS])
    reasoning = sorted([m for m in all_models if m in REASONING_MODELS])
    models_sorted = non_reasoning + reasoning
    
    # Convert to categorical with explicit ordering
    df['Model'] = pd.Categorical(df['Model'], categories=models_sorted, ordered=True)
    df = df.sort_values('Model')  # Ensure proper ordering
    
    # Create plot
    fig, ax = plt.subplots(figsize=(14, 7))
    
    # Color palette
    difficulty_palette = {
        "Small": "#4e79a7",  # Blue
        "Medium": "#f28e2b",  # Orange
        "Long": "#59a14f"    # Green
    }
    
    # Bar positioning
    x = np.arange(len(models_sorted))
    width = 0.25
    
    # Plot bars for each difficulty
    for i, difficulty in enumerate(["Small", "Medium", "Long"]):
        bars = ax.bar(x + i*width, df[difficulty], width,
                      label=difficulty,
                      color=difficulty_palette[difficulty],
                      edgecolor='black')
        
        # Highlight reasoning models
        for j, model in enumerate(models_sorted):
            if model in REASONING_MODELS:
                bars[j].set_edgecolor('red')
                bars[j].set_linewidth(2)
                bars[j].set_hatch('///')
    
    
    # Custom legend
    legend_elements = [
        Patch(facecolor=difficulty_palette[d], label=d) 
        for d in ["Small", "Medium", "Long"]
    ]
    legend_elements.append(
        Patch(facecolor='white', edgecolor='red', hatch='///', 
              linewidth=2, label='Reasoning Model')
    )
    
    # Plot formatting
    quant_label = "Quantized" if quantize_type == "yes" else "Non-Quantized"
    # ax.set_title(
    #     f'{prediction_type.capitalize()} Prediction Accuracy ({quant_label})\n',
    #     pad=20, fontsize=14
    # )
    #ax.set_xlabel('Model', labelpad=10)
    ax.set_ylabel('Accuracy', labelpad=10)
    ax.set_xticks(x + width)
    ax.set_xticklabels(models_sorted, rotation=45, ha='right', fontsize=10)
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    ax.legend(
        handles=legend_elements,
        loc='upper right',        
        framealpha=0.9,
        fontsize=9
    )
    
    plt.tight_layout()
    plt.savefig(
        f'{prediction_type}_accuracy_{quantize_type}_length.png', 
        dpi=300, 
        bbox_inches='tight'
    )
    plt.show()

# Load data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/Plotting_Results/RQ2/model_accuracy_analysis.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Generate all four plots
for prediction_type in ["input", "output"]:
    for quantize_type in ["yes", "no"]:
        plot_quantization_accuracy(data, prediction_type, quantize_type)