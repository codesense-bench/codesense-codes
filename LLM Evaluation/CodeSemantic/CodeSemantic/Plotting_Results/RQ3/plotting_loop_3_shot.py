import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# Model categorization
REASONING_MODELS = {
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "granite-3.2-8b-instruct",
    "granite-3.2-8b-instruct-preview",
}
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
}

# Load data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/loop_Accuracy_Results/loop_python_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Process data with quantization and shots
loop_data = []
for record in data:
    loop_data.append({
        "Model": record["Model"],
        "Accuracy": record["accuracy"],
        "Settings": record["settings"],
        "Quantization": "Abstract" if record["quantization"] == "yes" else "Concrete",
        "Shot": record["shot"],
        "IsReasoning": record["Model"] in REASONING_MODELS,
        "IsPaid": record["Model"] in PAID_MODELS
    })

df = pd.DataFrame(loop_data)

# Exclude paid models from the DataFrame
df = df[~df['Model'].isin(PAID_MODELS)]

# Filter to relevant settings
settings_to_plot = ['body', 'after']

# Sort models
def model_priority(model):
    if model in REASONING_MODELS:
        return (2, model)
    elif model in PAID_MODELS:
        return (1, model)
    else:
        return (0, model)

# Plotting parameters
SHOTS = [3]  # Selected shots to display
COLORS = {'Abstract': '#1f77b4', 'Concrete': '#ff7f0e'}
BAR_WIDTH = 0.25
EDGE_COLORS = {'Reasoning': 'red', 'Free': 'black'}
HATCHES = {'Reasoning': '///', 'Free': None}

for setting in settings_to_plot:
    # Filter data for current setting
    setting_df = df[df['Settings'] == setting]
    
    # Sort models and prepare plot
    models_sorted = sorted(setting_df['Model'].unique(), key=model_priority)
    x = np.arange(len(models_sorted))
    
    fig, ax = plt.subplots(figsize=(14, 7))
    
    # Plot bars for each shot and quantization type
    for shot_idx, shot in enumerate(SHOTS):
        for quant_idx, (quant_type, color) in enumerate(COLORS.items()):
            offset = (shot_idx - 1) * BAR_WIDTH + quant_idx * BAR_WIDTH/2
            accuracies = []
            
            for model in models_sorted:
                # Get accuracy for this combination
                acc = setting_df[(setting_df['Model'] == model) & 
                                 (setting_df['Shot'] == shot) & 
                                 (setting_df['Quantization'] == quant_type)]
                accuracies.append(acc['Accuracy'].values[0] if not acc.empty else 0)
                
                # Apply model category styling
                model_type = 'Reasoning' if model in REASONING_MODELS else 'Free'
                
                ax.bar(x[models_sorted.index(model)] + offset, 
                       accuracies[-1], 
                       width=BAR_WIDTH/2,
                       color=color,
                       edgecolor=EDGE_COLORS[model_type],
                       hatch=HATCHES[model_type],
                       linewidth=1)
    
    # Configure plot appearance
    #ax.set_title(f'{setting.capitalize()} Setting Accuracy Comparison', pad=20, fontsize=14)
    ax.set_xticks(x + BAR_WIDTH/2)
    ax.set_xticklabels(models_sorted, rotation=45, ha='right')
    ax.set_ylabel('Accuracy')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    
    # Create combined legend
    combined_legend = [
        Patch(facecolor=COLORS['Abstract'], label='Abstract Prediction'),
        Patch(facecolor=COLORS['Concrete'], label='Concrete Prediction')
    ]
    
    # Model legends
    model_legend = [
        Patch(facecolor='white', edgecolor=EDGE_COLORS['Reasoning'], 
              hatch=HATCHES['Reasoning'], label='Reasoning Models'),
        Patch(facecolor='white', edgecolor=EDGE_COLORS['Free'], 
              label='Free Models')
    ]
    
    # Add combined legends to plot inside the figure area
    ax.legend(handles=combined_legend + model_legend, loc='upper right', fontsize=10, bbox_to_anchor=(1, 1))
    
    plt.tight_layout()
    plt.savefig(f'{setting}_quant_shot_comparision.png', dpi=300, bbox_inches='tight')
    plt.show()
