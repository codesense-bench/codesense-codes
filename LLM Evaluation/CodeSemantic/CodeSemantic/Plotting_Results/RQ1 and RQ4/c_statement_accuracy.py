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
                "Quant": "no"  # Add explicitly for consistency
            })

type_df = pd.DataFrame(type_acc)

# Map type labels to nicer names
def map_labels(label):
    label_mapping = {
        "API": "Function Call",
        "Assignment": "Variable Assignment",
        "Arithmetic Assignment": "Arithmetic",
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

# Model-specific plots with reasoning distinction
REASONING_MODELS = ["DeepReasoner", "CoT-LLM", "LLaMa-CoT"]  # Example, replace with actual model names

# Filter relevant models
models = type_df['Model'].unique()
reasoning_models = [m for m in models if m in REASONING_MODELS]
non_reasoning_models = [m for m in models if m not in REASONING_MODELS]
sorted_models = non_reasoning_models + reasoning_models

type_df = type_df[type_df['Model'].isin(sorted_models)]
type_df['Model'] = pd.Categorical(type_df['Model'], categories=sorted_models, ordered=True)

avg_acc = type_df.groupby(["Model", "Type"])["Accuracy"].mean().unstack()

plt.figure(figsize=(14, 7))
colors = sns.color_palette("Paired", len(avg_acc.columns))

n_models = len(avg_acc.index)
n_types = len(avg_acc.columns)
bar_width = 0.8 / n_types
x = np.arange(n_models)

# Create bars with reasoning indicators
for i, stype in enumerate(avg_acc.columns):
    for j, model in enumerate(avg_acc.index):
        is_reasoning = model in REASONING_MODELS
        hatch = '///' if is_reasoning else None
        edgecolor = 'red' if is_reasoning else 'black'

        plt.bar(x[j] + i * bar_width, avg_acc[stype][j],
                width=bar_width,
                color=colors[i],
                edgecolor=edgecolor,
                hatch=hatch)

# Create legend elements
legend_elements = []
for i, stype in enumerate(avg_acc.columns):
    legend_elements.append(Patch(facecolor=colors[i], label=stype))
legend_elements.append(Patch(facecolor='white', edgecolor='red',
                             hatch='///', label='Reasoning Model'))
legend_elements.append(Patch(facecolor='white', edgecolor='black',
                             label='Non-Reasoning Model'))

plt.xlabel("Model")
plt.ylabel("Average Accuracy")
plt.title("C Code: Accuracy by Model and Statement Type (Non-Quantized)")
plt.xticks(x + (n_types - 1) * bar_width / 2, avg_acc.index, rotation=45, ha='right')
plt.ylim(0, 1.0)

plt.legend(handles=legend_elements, title="Legend",
           bbox_to_anchor=(1.05, 1), loc='upper left')

plt.grid(axis="y", linestyle='--', alpha=0.7)
plt.tight_layout()
plt.savefig("c_model_statement_accuracy_non_quant_0_shot.png", dpi=300, bbox_inches="tight")
plt.show()
