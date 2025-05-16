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

    loop_data.append({
        "Model": record["Model"],
        "Accuracy": record["accuracy"],
        "Shots": record["shot"],
        "LoopSetting": record["settings"],
        "quantization": record["quantization"],
        "CoT": record["CoT"],  
        "incontext": record.get("incontext", "different"),
        "IsReasoning": record["Model"] in REASONING_MODELS
    })

df = pd.DataFrame(loop_data)
print("Total records:", len(df))

# Filter for required condition: shot = 3, incontext = different, quantization = no
df = df[(df['quantization'] == 'no') & (df['Shots'] == 3) & (df['incontext'] == 'different') & (df['LoopSetting'] == "after")]
print("Filtered records:", len(df))
print(df)

# Aggregate accuracy by Model and CoT
df = df.groupby(['Model', 'CoT']).agg({
    'Accuracy': 'mean',
    'IsReasoning': 'first'
}).reset_index()

# Prepare model order: Non-reasoning models first, reasoning models next
non_reasoning_models = sorted([model for model in df['Model'].unique() if model not in REASONING_MODELS])
reasoning_models = sorted([model for model in df['Model'].unique() if model in REASONING_MODELS])
models_sorted = non_reasoning_models + reasoning_models

df['Model'] = pd.Categorical(df['Model'], categories=models_sorted, ordered=True)

# Bar plot: Two bars per model (CoT = no and CoT = yes)
x = np.arange(len(models_sorted))
width = 0.35

palette = {"no": "#4e79a7", "yes": "#f28e2b"}

fig, ax = plt.subplots(figsize=(14, 7))

for i, cot_value in enumerate(["no", "yes"]):
    cot_data = df[df['CoT'] == cot_value]
    # Reindex to ensure all models are present
    cot_data = cot_data.set_index('Model').reindex(models_sorted, fill_value=0).reset_index()

    bars = ax.bar(x + i * width - width/2, cot_data['Accuracy'], width,
                  label=f'CoT = {cot_value}', color=palette[cot_value], edgecolor='black')

    # Add reasoning model indicators
    for j, model in enumerate(cot_data['Model']):
        if model in REASONING_MODELS:
            bars[j].set_edgecolor('red')
            bars[j].set_linewidth(1.5)
            bars[j].set_hatch('///')

# Add separation line between non-reasoning and reasoning models
if len(non_reasoning_models) > 0 and len(reasoning_models) > 0:
    sep_pos = len(non_reasoning_models) - 0.5
    ax.axvline(sep_pos, color='gray', linestyle='--', linewidth=1, alpha=0.7)

# Custom legend
legend_elements = [
    Patch(facecolor=palette["no"], label='CoT = no'),
    Patch(facecolor=palette["yes"], label='CoT = yes'),
    Patch(facecolor='white', edgecolor='red', hatch='///', linewidth=1.5, label='Reasoning Model'),
    Patch(facecolor='white', edgecolor='black', label='Non-Reasoning Model')
]

ax.set_xlabel('Model', labelpad=10)
ax.set_ylabel('Accuracy', labelpad=10)
ax.set_xticks(x)
ax.set_xticklabels(models_sorted, rotation=45, ha='right')
ax.set_ylim(0, 1.1)
ax.grid(axis='y', linestyle='--', alpha=0.3)
ax.legend(handles=legend_elements, bbox_to_anchor=(1, 1), loc='upper right')

plt.tight_layout()
plt.savefig('loop_accuracy_CoT_different_incontext.png', dpi=300, bbox_inches='tight')
plt.show()
