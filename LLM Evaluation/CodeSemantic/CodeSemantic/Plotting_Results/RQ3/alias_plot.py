import json
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# Define Reasoning Models
REASONING_MODELS = {
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "granite-3.2-8b-instruct",
    "granite-3.2-8b-instruct-preview",
}

# Define Paid Models
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
}

# Load JSONL data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/alias_Accuracy_Results/alias_c_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Filter & annotate data
alias_data = []
for record in data:
    if record.get("quantization") == "no" and record.get("shot") == 0:
        alias_data.append({
            "Model": record["Model"],
            "Accuracy": record["accuracy"],
            "IsReasoning": record["Model"] in REASONING_MODELS,
            "IsPaid": record["Model"] in PAID_MODELS
        })

df = pd.DataFrame(alias_data)

# Custom sort: Free Non-Reasoning -> Paid -> Reasoning
def model_priority(model):
    if model in REASONING_MODELS:
        return (2, model)  # Reasoning models last
    elif model in PAID_MODELS:
        return (1, model)  # Paid models second
    else:
        return (0, model)  # Free Non-Reasoning first

models_sorted = sorted(df['Model'].unique(), key=model_priority)
df['Model'] = pd.Categorical(df['Model'], categories=models_sorted, ordered=True)
df = df.sort_values('Model')

# Plotting
plt.figure(figsize=(12, 6))
ax = plt.gca()

# Color palette
palette = {
    'Reasoning': "#4e79a7",  # Blue
    'Paid': "#59a14f",       # Green
    'Free': "#f28e2b"        # Orange
}

# Determine color, edgecolor, hatch per model
colors = []
edgecolors = []
hatches = []

for _, row in df.iterrows():
    if row['IsReasoning']:
        colors.append(palette['Reasoning'])
        edgecolors.append('red')
        hatches.append('///')
    elif row['IsPaid']:
        colors.append(palette['Paid'])
        edgecolors.append('green')
        hatches.append('\\\\\\')
    else:
        colors.append(palette['Free'])
        edgecolors.append('black')
        hatches.append(None)

# Plot bars
bars = ax.bar(
    x=range(len(df)),
    height=df['Accuracy'],
    color=colors,
    edgecolor=edgecolors,
    hatch=hatches
)

# Annotate values on bars
# for bar in bars:
#     height = bar.get_height()
#     ax.text(bar.get_x() + bar.get_width()/2, height + 0.01,
#             f'{height:.2f}', ha='center', va='bottom', fontsize=9)

# Legend elements
legend_elements = [
    Patch(facecolor=palette['Reasoning'], edgecolor='red', hatch='///', label='Reasoning Models'),
    Patch(facecolor=palette['Paid'], edgecolor='green', hatch='\\\\\\', label='Proprietary Models'),
    Patch(facecolor=palette['Free'], edgecolor='black', label='Non-Reasoning Models')
]

# Axis labels & formatting
# ax.set_title('Aliasing Prediction Accuracy', pad=20, fontsize=14)
# ax.set_xlabel('Model', labelpad=10)
ax.set_ylabel('Accuracy', labelpad=10)
ax.set_xticks(range(len(df)))
ax.set_xticklabels(df['Model'], rotation=45, ha='right')
ax.set_ylim(0, 1.1)
ax.grid(axis='y', linestyle='--', alpha=0.3)
ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.95, 0.95), framealpha=1)

plt.tight_layout()
plt.savefig('aliasing_accuracy.png', dpi=300, bbox_inches='tight')
plt.show()
