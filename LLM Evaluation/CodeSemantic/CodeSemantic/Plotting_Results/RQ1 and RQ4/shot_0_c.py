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
with open("/home/XXX/CodeSemantic/CodeSemantic/statement_Accuracy_Results/statement_c_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))

# Prepare type-level accuracy data
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

# Apply label mapping
type_df['Type'] = type_df['Type'].apply(map_labels)

# ---------------------- Function for Plotting ------------------------

def plot_model_accuracy_by_type(df, quantization, output_file, plot_title):
    # Filter based on quantization type
    filtered_df = df[df["Quant"] == quantization]

    # Pivot the data
    pivot_df = filtered_df.pivot_table(index="Type", columns="Model", values="Accuracy")

    if pivot_df.empty:
        print(f"No data found for quantization = '{quantization}'. Skipping plot.")
        return

    # Desired statement type order
    desired_order = ["Arithmetic", "Function Call", "Variable", "Boolean", "Constant"]
    pivot_df = pivot_df.reindex(desired_order)

    # Plot settings
    plt.figure(figsize=(14, 8))

    # Consistent model order & colors
    all_models = sorted(pivot_df.columns.unique())
    colors = sns.color_palette("husl", len(all_models))
    model_colors = dict(zip(all_models, colors))

    # Positioning
    n_types = len(pivot_df.index)
    group_width = 0.8
    x_base = np.arange(n_types)

    # Plot bars without sorting models per statement type
    for i, stmt_type in enumerate(pivot_df.index):
        model_acc = pivot_df.loc[stmt_type]
        n_models = len(all_models)
        bar_width = group_width / n_models

        x_pos = x_base[i] - group_width/2 + np.arange(n_models) * bar_width + bar_width/2

        for j, model in enumerate(all_models):
            acc = model_acc.get(model, 0)  # Handle NaN as 0
            plt.bar(x_pos[j], acc, width=bar_width*0.9, 
                    color=model_colors[model], edgecolor='black')

            # Add labels on bars
            if bar_width > 0.1:
                plt.text(x_pos[j], acc/2, f"{model}\n{acc:.2f}", 
                         ha='center', va='center', rotation=90, fontsize=8)

    # Customize plot appearance
    #plt.xlabel("Statement Type")
    plt.ylabel("Accuracy")
    #plt.title(plot_title)
    plt.xticks(x_base, pivot_df.index, rotation=45, ha='right')
    plt.ylim(0, 1.0)

    # Legend
    legend_elements = [plt.Rectangle((0,0), 1, 1, color=model_colors[model], label=model) 
                       for model in all_models]
    plt.legend(handles=legend_elements, bbox_to_anchor=(1.05, 1), 
               loc='upper left', title="Models")

    plt.grid(axis="y", linestyle="--", alpha=0.7)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300, bbox_inches="tight")
    plt.show()

# ---------------------- Generate Plots ------------------------

# Plot for non-quantized models
plot_model_accuracy_by_type(
    type_df, 
    quantization="no", 
    output_file="model_accuracy_by_statement_type_C.png",
    plot_title="Model Accuracy by Statement Type (C)"
)

# Plot for quantized models
plot_model_accuracy_by_type(
    type_df, 
    quantization="yes", 
    output_file="quantized_model_accuracy_by_statement_type_C.png",
    plot_title="Quantized Model Accuracy by Statement Type"
)