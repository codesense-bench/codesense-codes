import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# Set professional style
sns.set_style("whitegrid")
plt.rcParams['figure.facecolor'] = 'white'
plt.rcParams['axes.facecolor'] = 'white'

# Load and process data
data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/statement_Accuracy_Results/statement_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

type_acc = []
for record in data:
    if (record.get("CoT") == "no" and 
        record.get("shot") == 0 and 
        record.get("Incontext") == "different"):
        for typ, acc in record["type_accuracy"].items():
            type_acc.append({
                "Type": typ,
                "Accuracy": acc,
                "Model": record["Model"],
                "Quant": record["quantization"]
            })

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

# Filter for non-quantized models (or change to "yes" for quantized)
quant_df = type_df[type_df["Quant"] == "no"]

# Pivot the data for plotting
pivot_df = quant_df.pivot_table(index="Type", columns="Model", values="Accuracy")

# # Create the plot with proper spacing
# plt.figure(figsize=(14, 8))

# Get all unique models and assign consistent colors
all_models = pivot_df.columns.unique()
colors = sns.color_palette("husl", len(all_models))
model_colors = dict(zip(all_models, colors))

# # Calculate positions and spacing
# n_types = len(pivot_df.index)
# group_width = 0.8  # Total width for each statement type group

# # Create x-axis positions for each statement type
# x_base = np.arange(n_types)  # Base positions for each statement type

# # Plot each statement type with sorted models
# for i, stmt_type in enumerate(pivot_df.index):
#     # Sort models by accuracy for this statement type
#     sorted_data = pivot_df.loc[stmt_type].sort_values()
#     sorted_models = sorted_data.index
#     sorted_acc = sorted_data.values
#     n_models = len(sorted_models)
#     bar_width = group_width / n_models  # Width of individual bars
    
#     # Calculate x positions for this group
#     x_pos = x_base[i] - group_width/2 + np.arange(n_models) * bar_width + bar_width/2
    
#     # Plot bars with consistent colors
#     for j, (model, acc) in enumerate(zip(sorted_models, sorted_acc)):
#         plt.bar(x_pos[j], acc, width=bar_width*0.9, 
#                color=model_colors[model], edgecolor='black')
        
#         # Add model labels if space permits
#         if bar_width > 0.1:
#             plt.text(x_pos[j], acc/2, f"{model}\n{acc:.2f}", 
#                     ha='center', va='center', rotation=90, fontsize=8)

# # Customize the plot
# plt.xlabel("Statement Type")
# plt.ylabel("Accuracy")
# plt.title("Model Accuracy by Statement Type")
# plt.xticks(x_base, pivot_df.index, rotation=45, ha='right')
# plt.ylim(0, 1.0)

# # Create custom legend with consistent colors
# legend_elements = [plt.Rectangle((0,0), 1, 1, color=model_colors[model], label=model) 
#                   for model in all_models]
# plt.legend(handles=legend_elements, bbox_to_anchor=(1.05, 1), 
#            loc='upper left', title="Models")

# plt.grid(axis="y", linestyle="--", alpha=0.7)
# plt.tight_layout()
# plt.savefig("model_accuracy_by_statement_type_sorted_0_shot.png", dpi=300, bbox_inches="tight")
# plt.show()

# Define desired statement type order
desired_order = ["Function Call", "Arithmetic", "Variable", "Boolean", "Constant"]

# Filter and reorder pivot_df to match desired statement type order
pivot_df = pivot_df.reindex(desired_order)

# Plot without sorting models per statement type
plt.figure(figsize=(14, 8))

n_types = len(pivot_df.index)
n_models = len(pivot_df.columns)
group_width = 0.8  # Total width for each statement type group

# Base x-axis positions for statement types
x_base = np.arange(n_types)

bar_width = group_width / n_models  # Width of individual bars

# Loop through models in fixed order
for j, model in enumerate(pivot_df.columns):
    acc_values = pivot_df[model].values
    
    # Calculate x positions for current model bars
    x_pos = x_base - group_width/2 + j * bar_width + bar_width/2
    
    plt.bar(x_pos, acc_values, width=bar_width*0.9, 
            color=model_colors[model], edgecolor='black', label=model)
    
    # Add accuracy labels if space allows
    if bar_width > 0.1:
        for i, acc in enumerate(acc_values):
            plt.text(x_pos[i], acc/2, f"{model}\n{acc:.2f}", 
                     ha='center', va='center', rotation=90, fontsize=8)

# Customize plot appearance
#plt.xlabel("Statement Type")
plt.ylabel("Accuracy")
#plt.title("Model Accuracy by Statement Type")
plt.xticks(x_base, desired_order, rotation=45, ha='right')
plt.ylim(0, 1.0)

# Create custom legend
legend_elements = [plt.Rectangle((0,0), 1, 1, color=model_colors[model], label=model) 
                   for model in pivot_df.columns]
# plt.legend(handles=legend_elements, bbox_to_anchor=(1.05, 1), 
#            loc='upper left', title="Models")

plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.tight_layout()
plt.savefig("model_accuracy_by_statement_type_python.png", dpi=300, bbox_inches="tight")
plt.show()

