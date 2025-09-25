import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.patches import Patch

# Set professional style
sns.set_style("whitegrid")
plt.rcParams['figure.facecolor'] = 'white'
plt.rcParams['axes.facecolor'] = 'white'

# Load C results
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/statement_Accuracy_Results/statement_c_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Process type_accuracy for non-quantized, 0-shot, Incontext = different, CoT = no
type_acc = []
for record in data:
    if (record.get("CoT") == "no" and 
        record.get("shot") == 0 and 
        record.get("Incontext") == "different" and 
        record.get("quantization") == "no"):
        
        for typ, acc in record["type_accuracy"].items():
            type_acc.append({
                "Type": typ,
                "Accuracy": acc,
                "Model": record["Model"],
                "Quant": "no"
            })

type_df = pd.DataFrame(type_acc)

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

# Map type labels to nicer names
def map_labels(label):
    label_mapping = {
        "API": "Function Call",
        "Assignment": "Variable",
        "Arithmetic Assignment": "Arithmetic",
        "Constant Assignment": "Constant",
        "Branch": "Boolean"
    }
    return label_mapping.get(label, label)

type_df['Type'] = type_df['Type'].apply(map_labels)

# Combined average accuracy plot (Non-Quantized only)
plt.figure(figsize=(10, 6))

avg_type_acc = type_df.groupby("Type")["Accuracy"].mean().sort_values()

bars = plt.bar(avg_type_acc.index, avg_type_acc.values, width=0.8,
               color='#f28e2b', edgecolor='black')

plt.xlabel("Statement Type")
plt.ylabel("Average Accuracy")
plt.title("C Code: Average Accuracy by Statement Type (Non-Quantized)")
plt.xticks(rotation=45, ha='right')
plt.ylim(0, 1.0)

for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width()/2., height,
             f'{height:.2f}', ha='center', va='bottom', fontsize=9)

plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("c_average_statement_accuracy_non_quant_0_shot.png", dpi=300, bbox_inches="tight")
plt.show()

# Model-specific plots with reasoning and paid distinctions
# Filter relevant models and sort
all_models = type_df['Model'].unique()
# Updated model sorting logic
sorted_models = sorted(
    all_models,
    key=lambda x: (
        # Primary sort: 0=non-reasoning, 1=paid, 2=reasoning
        1 if x in PAID_MODELS else 2 if x in REASONING_MODELS else 0,
        # Secondary sort: alphabetical
        x
    )
)
type_df = type_df[type_df['Model'].isin(sorted_models)]
type_df['Model'] = pd.Categorical(type_df['Model'], categories=sorted_models, ordered=True)

avg_acc = type_df.groupby(["Model", "Type"])["Accuracy"].mean().unstack()

plt.figure(figsize=(16, 8))
colors = sns.color_palette("Paired", len(avg_acc.columns))

n_models = len(avg_acc.index)
n_types = len(avg_acc.columns)
bar_width = 0.8 / n_types
x = np.arange(n_models)

# Create bars with indicators
for i, stype in enumerate(avg_acc.columns):
    for j, model in enumerate(avg_acc.index):
        is_reasoning = model in REASONING_MODELS
        is_paid = model in PAID_MODELS
        
        # Visual properties
        edgecolor = 'darkred' if is_reasoning else 'darkblue' if is_paid else 'black'
        hatch = '////' if is_reasoning else '....' if is_paid else None
        alpha = 0.9 if is_paid else 1.0  # Paid models slightly faded

        plt.bar(x[j] + i * bar_width, avg_acc[stype][j],
                width=bar_width,
                color=colors[i],
                edgecolor=edgecolor,
                alpha=alpha,
                hatch=hatch,
                linewidth=1.2)

# Create legend elements
legend_elements = [
    *[Patch(facecolor=colors[i], label=stype) for i, stype in enumerate(avg_acc.columns)],
    Patch(facecolor='white', edgecolor='darkred', hatch='////', label='Reasoning Model'),
    Patch(facecolor='white', edgecolor='darkblue', hatch='....', label='Paid Model'),
    Patch(facecolor='white', edgecolor='black', label='Base Model')
]

plt.xlabel("Model")
plt.ylabel("Average Accuracy")
plt.title("C Code: Accuracy by Model and Statement Type")
plt.xticks(x + (n_types - 1) * bar_width / 2, avg_acc.index, rotation=45, ha='right')
plt.ylim(0, 1.0)

plt.legend(handles=legend_elements, title="Categories",
           bbox_to_anchor=(1.05, 1), loc='upper left')

plt.grid(axis="y", linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig("c_model_statement_accuracy_non_quant_0_shot.png", dpi=300, bbox_inches="tight")
plt.show()