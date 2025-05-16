import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from matplotlib.patches import Patch

# Set professional style
sns.set_style("whitegrid")
plt.rcParams['figure.facecolor'] = 'white'
plt.rcParams['axes.facecolor'] = 'white'

# Paid proprietary models set
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
}

# Load and process data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/statement_Accuracy_Results/statement_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Process data for model comparison
processed = []
for record in data:
    if (record.get("CoT") == "no" and 
        record.get("Incontext") == "different" and
        record.get("shot") in [0, 3]):
        processed.append({
            'Model': record['Model'],
            'shot': record['shot'],
            'Quant': record['quantization'],
            'accuracy': record['accuracy']
        })

df = pd.DataFrame(processed)

df = df[~df['Model'].isin(PAID_MODELS)]
# Define color palette for models
all_models = df['Model'].unique()
colors = sns.color_palette("husl", len(all_models))
model_colors = dict(zip(sorted(all_models), colors))

def plot_quant_comparison(shot_number):
    # Filter and pivot data
    shot_df = df[df['shot'] == shot_number]
    pivot_df = shot_df.pivot_table(index='Model', columns='Quant', values='accuracy').sort_index()
    
    # Setup plot
    plt.figure(figsize=(12, 6))
    models = pivot_df.index
    x = np.arange(len(models))
    bar_width = 0.4
    
    # Fixed colors
    quantized_color = '#1f77b4'  # Blue
    non_quantized_color = '#2ca02c'   # Yellow
    
    # Plot bars
    for i, model in enumerate(models):
        acc_yes = pivot_df.loc[model, 'yes'] if 'yes' in pivot_df.columns else 0
        acc_no = pivot_df.loc[model, 'no'] if 'no' in pivot_df.columns else 0
        
        plt.bar(x[i] - bar_width/2, acc_yes, width=bar_width,
                color=quantized_color, edgecolor='black', label='Abstract' if i==0 else "")
        plt.bar(x[i] + bar_width/2, acc_no, width=bar_width,
                color=non_quantized_color, edgecolor='black', label='Concrete' if i==0 else "")
    
    # Formatting
    plt.xticks(x, models, rotation=45, ha='right')
    plt.ylabel('Accuracy', fontsize=12)
    #plt.title(f'Model Accuracy Comparison ({shot_number}-shot)', fontsize=14)
    plt.ylim(0, 1.0)
    
    # Custom legend
    plt.legend(loc='upper right', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(f"quant_comparison_{shot_number}-shot.png", dpi=300, bbox_inches='tight')
    plt.show()

# Generate plots
plot_quant_comparison(0)
plot_quant_comparison(3)
