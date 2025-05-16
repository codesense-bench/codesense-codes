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

# Define paid models to exclude
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
    "gpt-4o-mini"
}

# Load and process data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/loop_Accuracy_Results/loop_python_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Process data into DataFrame and handle duplicates
loop_data = []
for record in data:
    if record["Model"] in PAID_MODELS:
        continue  # Skip paid models

    loop_data.append({
        "Model": record["Model"],
        "Accuracy": record["accuracy"],
        "Shots": record["shot"],
        "LoopSetting": record["settings"],
        "quantization": record["quantization"],
        "IsReasoning": record["Model"] in REASONING_MODELS
    })

df = pd.DataFrame(loop_data)
print(len(df))
df = df[df['quantization'] == 'no'] 
print(len(df))

df = df.groupby(['Model', 'LoopSetting', 'Shots']).agg({
    'Accuracy': 'mean',  
    'IsReasoning': 'first'  
}).reset_index()


loop_settings = df['LoopSetting'].unique()


for loop_setting in loop_settings:
    setting_df = df[df['LoopSetting'] == loop_setting].copy()


    non_reasoning_models = sorted([model for model in setting_df['Model'].unique() 
                                   if model not in REASONING_MODELS])
    reasoning_models = sorted([model for model in setting_df['Model'].unique() 
                               if model in REASONING_MODELS])
    models_sorted = non_reasoning_models + reasoning_models


    setting_df['Model'] = pd.Categorical(setting_df['Model'], 
                                         categories=models_sorted, 
                                         ordered=True)


    palette = {0: "#4e79a7", 3: "#f28e2b"}  


    x = np.arange(len(models_sorted))
    width = 0.35
    fig, ax = plt.subplots(figsize=(14, 7))


    if len(non_reasoning_models) > 0 and len(reasoning_models) > 0:
        sep_pos = len(non_reasoning_models) - 0.5
        ax.axvline(sep_pos, color='gray', linestyle='--', linewidth=1, alpha=0.7)

    # Plot bars for each shot configuration
    for i, shots in enumerate([0, 3]):
        shot_data = setting_df[setting_df['Shots'] == shots]
        # Handle missing models by reindexing
        shot_data = shot_data.set_index('Model').reindex(models_sorted, fill_value=0).reset_index()

        bars = ax.bar(x + i * width - width/2, shot_data['Accuracy'], width,
                      label=f'{shots}-shot', color=palette[shots], edgecolor='black')

        # Add reasoning model indicators
        for j, model in enumerate(shot_data['Model']):
            if model in REASONING_MODELS:
                bars[j].set_edgecolor('red')
                bars[j].set_linewidth(1.5)
                bars[j].set_hatch('///')

    # Custom legend
    legend_elements = [
        Patch(facecolor=palette[0], label='0-shot'),
        Patch(facecolor=palette[3], label='3-shot'),
        Patch(facecolor='white', edgecolor='red', hatch='///', linewidth=1.5, label='Reasoning Model'),
        Patch(facecolor='white', edgecolor='black', label='Non-Reasoning Model')
    ]

    #ax.set_title(f'Loop Prediction Accuracy ({loop_setting})', pad=20, fontsize=14)
    ax.set_xlabel('Model', labelpad=10)
    ax.set_ylabel('Accuracy', labelpad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(models_sorted, rotation=45, ha='right')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    ax.legend(handles=legend_elements, bbox_to_anchor=(1, 1), loc='upper right')

    plt.tight_layout()
    plt.savefig(f'loop_accuracy_shot_{loop_setting}.png', dpi=300, bbox_inches='tight')
    plt.show()
