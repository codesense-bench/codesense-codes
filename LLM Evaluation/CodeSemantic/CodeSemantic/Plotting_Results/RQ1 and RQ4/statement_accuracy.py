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

# Load and process data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/statement_Accuracy_Results/statement_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

type_acc = []
count = 0
for record in data:
    if (record.get("CoT") == "no" and 
        record.get("shot") == 0 and 
        record.get("Incontext") == "different"):
        count += 1
        for typ, acc in record["type_accuracy"].items():
            type_acc.append({
                "Type": typ,
                "Accuracy": acc,
                "Model": record["Model"],
                "CoT": record["CoT"],
                "Quant": record["quantization"],
                "shot": record.get("shot"),
                "Incontext": record.get("Incontext")
            })
print(count)
type_df = pd.DataFrame(type_acc)

# Define label mapping
def map_labels(label):
    label_mapping = {
        "API": "Function Call",
        "Assignment": "Variable",
        "Arithmetic Assignment": "Arithmetic",
        "Constant Assignment": "Constant",
        "Branch": "Boolean"
    }
    return label_mapping.get(label, label)

# Apply label mapping to the DataFrame
type_df['Type'] = type_df['Type'].apply(map_labels)

# 1. Combined average accuracy plot
plt.figure(figsize=(12, 6))

combined_avg = type_df.groupby(["Type", "Quant"])["Accuracy"].mean().unstack()
combined_avg = combined_avg.rename(columns={"yes": "Quantized", "no": "Non-Quantized"})

x = np.arange(len(combined_avg))
width = 0.35

rects1 = plt.bar(x - width/2, combined_avg["Quantized"], width, 
                label='Quantized', color='#4e79a7', edgecolor='black')
rects2 = plt.bar(x + width/2, combined_avg["Non-Quantized"], width, 
                label='Non-Quantized', color='#f28e2b', edgecolor='black')

plt.xlabel("Statement Type")
plt.ylabel("Average Accuracy")
plt.title("Average Accuracy by Statement Type and Quantization")
plt.xticks(x, combined_avg.index, rotation=45, ha='right')
plt.ylim(0, 1.0)
plt.legend()

plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("combined_average_statement_accuracy_0_shot.png", dpi=300, bbox_inches="tight")
plt.show()

# 2. Individual average accuracy plots
for quant in ["yes", "no"]:
    quant_label = "Quantized" if quant == "yes" else "Non-Quantized"
    quant_df = type_df[type_df["Quant"] == quant]
    avg_type_acc = quant_df.groupby("Type")["Accuracy"].mean().sort_values()
    
    plt.figure(figsize=(10, 6))
    
    bars = plt.bar(avg_type_acc.index, avg_type_acc.values, width=0.8,
                  color='#4e79a7' if quant == "yes" else '#f28e2b', 
                  edgecolor='black')
    
    plt.xlabel("Statement Type")
    plt.ylabel("Average Accuracy")
    plt.title(f"Average Accuracy by Statement Type ({quant_label})")
    plt.xticks(rotation=45, ha='right')
    plt.ylim(0, 1.0)
    
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}', ha='center', va='bottom', fontsize=9)
    
    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig(f"average_statement_accuracy_quant_{quant}_0_shot.png", dpi=300, bbox_inches="tight")
    plt.show()

# 3. Model-specific plots (with Proprietary & Reasoning distinction)
for quant in ["yes", "no"]:
    quant_label = "Quantized" if quant == "yes" else "Non-Quantized"
    quant_df = type_df[type_df["Quant"] == quant]
    
    # Split models into reasoning, proprietary, and others
    models = quant_df['Model'].unique()
    reasoning_models = [m for m in models if m in REASONING_MODELS]
    paid_models = [m for m in models if m in PAID_MODELS]
    non_reasoning_models = [m for m in models if m not in REASONING_MODELS and m not in PAID_MODELS]
    
    # Combine ordering
    sorted_models = non_reasoning_models + paid_models + reasoning_models
    
    quant_df = quant_df[quant_df['Model'].isin(sorted_models)]
    quant_df['Model'] = pd.Categorical(quant_df['Model'], categories=sorted_models, ordered=True)
    
    avg_acc = quant_df.groupby(["Model", "Type"])["Accuracy"].mean().unstack()
    
    plt.figure(figsize=(14, 7))
    
    colors = sns.color_palette("Paired", len(avg_acc.columns))
    
    n_models = len(avg_acc.index)
    n_types = len(avg_acc.columns)
    bar_width = 0.8/n_types
    x = np.arange(n_models)
    
    for i, stype in enumerate(avg_acc.columns):
        for j, model in enumerate(avg_acc.index):
            is_reasoning = model in REASONING_MODELS
            is_paid = model in PAID_MODELS
            hatch = '///' if is_reasoning else ('\\\\\\' if is_paid else None)
            edgecolor = 'red' if is_reasoning else ('green' if is_paid else 'black')
            alpha = 1.0 if (is_reasoning or is_paid) else 0.8
            
            plt.bar(x[j] + i*bar_width, avg_acc[stype][j], 
                    width=bar_width, 
                    color=colors[i],
                    edgecolor=edgecolor,
                    hatch=hatch,
                    alpha=alpha)
    
    # Custom legend
    legend_elements = []
    
    # Statement types legend
    for i, stype in enumerate(avg_acc.columns):
        legend_elements.append(Patch(facecolor=colors[i], label=stype))
    
    # Reasoning & Proprietary indicators
    legend_elements.append(Patch(facecolor='white', edgecolor='red', 
                                 hatch='///', label='Reasoning Model'))
    legend_elements.append(Patch(facecolor='white', edgecolor='green', 
                                 hatch='\\\\\\', label='Proprietary Model'))
    legend_elements.append(Patch(facecolor='white', edgecolor='black', 
                                 label='Non-Reasoning Model'))
    
    plt.xlabel("Model")
    plt.ylabel("Average Accuracy")
    plt.title(f"Accuracy by Model and Statement Type")
    plt.xticks(x + (n_types-1)*bar_width/2, avg_acc.index, rotation=45, ha='right')
    plt.ylim(0, 1.0)
    
    plt.legend(handles=legend_elements, title="Legend", 
               bbox_to_anchor=(1.05, 1), loc='upper left')
    
    plt.grid(axis="y", linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(f"model_statement_accuracy_quant_{quant}_0_shot.png", dpi=300, bbox_inches="tight")
    plt.show()
