import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# Define Reasoning & Paid models
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

# Load & process data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/loop_Accuracy_Results/loop_python_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Filter data: non-quantized, zero-shot only
loop_data = []
for record in data:
    if record.get("quantization") == "no" and record.get("shot") == 0:
        loop_data.append({
            "Model": record["Model"],
            "Accuracy": record["accuracy"],
            "Settings": record["settings"],
            "IsReasoning": record["Model"] in REASONING_MODELS,
            "IsPaid": record["Model"] in PAID_MODELS
        })

df = pd.DataFrame(loop_data)

# Sort models: Free Non-Reasoning → Paid → Reasoning
def model_priority(model):
    if model in REASONING_MODELS:
        return (2, model)
    elif model in PAID_MODELS:
        return (1, model)
    else:
        return (0, model)

models_sorted = sorted(df['Model'].unique(), key=model_priority)

# Assign categorical order
df['Model'] = pd.Categorical(df['Model'], categories=models_sorted, ordered=True)
df = df.sort_values('Model')

# Plotting
settings_order = ['after', 'body', 'iteration']  
settings = [s for s in settings_order if s in df['Settings'].unique()]
n_models = len(models_sorted)
n_settings = len(settings)
x = np.arange(n_models)
width = 0.2

DISPLAY_NAMES = {
    "after": "Post-loop",
    "body": "In-loop",
    "iteration": "Iteration" 
}

# Color palette for settings
setting_colors = plt.get_cmap('Set2').colors[:n_settings]

fig, ax = plt.subplots(figsize=(14, 7))

for i, setting in enumerate(settings):
    setting_df = df[df['Settings'] == setting].set_index('Model').reindex(models_sorted).reset_index()
    
    # Bar style: edge color & hatching based on category
    edgecolors = []
    hatches = []
    for _, row in setting_df.iterrows():
        if row['IsReasoning']:
            edgecolors.append('red')
            hatches.append('///')
        elif row['IsPaid']:
            edgecolors.append('green')
            hatches.append('\\\\\\')
        else:
            edgecolors.append('black')
            hatches.append(None)
    
    offset = (i - (n_settings-1)/2) * width
    bars = ax.bar(x + offset, setting_df['Accuracy'], width, label=setting, 
                  color=setting_colors[i],
                  edgecolor=edgecolors,
                  hatch=hatches)

# Legend for settings (body, after → renamed)
legend_elements = []
for i, setting in enumerate(settings):
    display_name = DISPLAY_NAMES.get(setting, setting)
    legend_elements.append(Patch(facecolor=setting_colors[i], label=display_name))

# Legend for model types
legend_elements.extend([
    Patch(facecolor='white', edgecolor='red', hatch='///', label='Reasoning Models'),
    Patch(facecolor='white', edgecolor='green', hatch='\\\\\\', label='Paid Models'),
    Patch(facecolor='white', edgecolor='black', label='Free Non-Reasoning Models')
])

# Configure plot appearance
# ax.set_title('Loop Prediction Accuracy across Settings', pad=20, fontsize=16)
# ax.set_xlabel('Model', labelpad=10)
ax.set_ylabel('Accuracy', labelpad=10)
ax.set_xticks(x)
ax.set_xticklabels(models_sorted, rotation=45, ha='right')
ax.set_ylim(0, 1.1)
ax.grid(axis='y', linestyle='--', alpha=0.3)
ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.99, 0.99), framealpha=1)


plt.tight_layout()
plt.savefig('loop_accuracy_combined.png', dpi=300, bbox_inches='tight')
plt.show()
