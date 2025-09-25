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
    "gpt-4o-mini",
}

# Load data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/loop_Accuracy_Results/loop_python_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Process data
loop_data = []
for record in data:
    loop_data.append({
        "Model": record["Model"],
        "Accuracy": record["accuracy"],
        "Settings": record["settings"],
        "Quantization": "Abstract" if record["quantization"] == "yes" else "Concrete",
        "Shot": record["shot"],
    })

df = pd.DataFrame(loop_data)

# Plotting parameters
settings_to_plot = ['body', 'after']
SHOTS = [3]
COLORS = {'Abstract': '#1f77b4', 'Concrete': '#ff7f0e'}
BAR_WIDTH = 0.35  # Width for each individual bar
GROUP_SPACING = 1  # Space between model groups

# Style configurations
MODEL_STYLES = {
    'Reasoning': {'edgecolor': 'red', 'hatch': '///', 'linewidth': 1.5},
    'Paid': {'edgecolor': 'green', 'hatch': '\\\\', 'linewidth': 1.5},
    'Free': {'edgecolor': 'black', 'hatch': None, 'linewidth': 1}
}

for setting in settings_to_plot:
    # Filter and sort data
    setting_df = df[df['Settings'] == setting]
    models = sorted(setting_df['Model'].unique(), key=lambda x: (
        0 if x in REASONING_MODELS else
        -1 if x in PAID_MODELS else
        -2, x
    ))
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 7))
    x = np.arange(len(models)) * GROUP_SPACING
    
    # Plot bars for each model
    for model_idx, model in enumerate(models):
        # Determine model category
        if model in REASONING_MODELS:
            category = 'Reasoning'
        elif model in PAID_MODELS:
            category = 'Paid'
        else:
            category = 'Free'
        
        style = MODEL_STYLES[category]
        
        # Calculate positions for both quantization types
        offsets = [-BAR_WIDTH/2, BAR_WIDTH/2]
        for q_idx, (q_type, color) in enumerate(COLORS.items()):
            x_pos = x[model_idx] + offsets[q_idx]
            
            acc = setting_df[
                (setting_df['Model'] == model) &
                (setting_df['Shot'] == SHOTS[0]) &
                (setting_df['Quantization'] == q_type)
            ]['Accuracy'].values
            
            height = acc[0] if len(acc) > 0 else 0
            
            ax.bar(x_pos, height, BAR_WIDTH,
                   color=color,
                   edgecolor=style['edgecolor'],
                   hatch=style['hatch'],
                   linewidth=style['linewidth'])
    
    # Configure axes
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right', fontsize=10)
    ax.set_xlim(-0.5 * GROUP_SPACING, (len(models)-0.5) * GROUP_SPACING)
    ax.set_ylabel('Accuracy', fontsize=12)
    ax.set_ylim(0, 1.1)
    ax.yaxis.grid(True, linestyle='--', alpha=0.3)
    
    # Create legends
    quant_legend = [
        Patch(facecolor=COLORS['Abstract'], label='Abstract Prediction'),
        Patch(facecolor=COLORS['Concrete'], label='Concrete Prediction')
    ]
    
    model_legend = [
        Patch(facecolor='white', **MODEL_STYLES['Reasoning'], label='Reasoning Models'),
        Patch(facecolor='white', **MODEL_STYLES['Paid'], label='Paid Models'),
        Patch(facecolor='white', **MODEL_STYLES['Free'], label='Free Models')
    ]
    
    ax.legend(handles=quant_legend + model_legend,
              loc='upper right',
              bbox_to_anchor=(1, 1),
              fontsize=10,
              ncol=2)
    
    # Final adjustments
    plt.tight_layout()
    plt.savefig(f'{setting}_comparison.png', dpi=300, bbox_inches='tight')
    plt.show()