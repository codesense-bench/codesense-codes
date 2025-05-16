import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Define reasoning models
REASONING_MODELS = {
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "granite-3.2-8b-instruct",
    "granite-3.2-8b-instruct-preview",
}

def plot_prediction_accuracy(results_path, prediction_type="input"):
    """
    Generate accuracy comparison plot for either input or output predictions
    
    Parameters:
    - results_path: Path to the JSONL results file
    - prediction_type: Either "input" or "output" (used for plot titles)
    """
    # Load and process data
    data = []
    with open(results_path, "r") as f:
        for line in f:
            data.append(json.loads(line))

    # Process data into DataFrame
    pred_acc = []
    for record in data:
        model_name = record["Model"]
        pred_acc.append({
            "Model": model_name,
            "Accuracy": record["accuracy"],
            "Quantization": "Quantized" if record["quantization"] == "yes" else "Concrete",
            "IsReasoning": model_name in REASONING_MODELS
        })

    df = pd.DataFrame(pred_acc)

    # Sort models: non-reasoning first, then reasoning
    models_sorted = sorted(df['Model'].unique(), key=lambda x: x in REASONING_MODELS)
    df['Model'] = pd.Categorical(df['Model'], categories=models_sorted, ordered=True)

    # Create the plot
    plt.figure(figsize=(14, 8))

    # Professional color palette
    palette = {"Quantized": "#4e79a7", "Concrete": "#59a14f"}

    # Get unique models and quantization types
    models = df['Model'].unique()
    quant_types = df['Quantization'].unique()
    n_models = len(models)
    n_quant_types = len(quant_types)

    # Create positions for bars
    x = np.arange(n_models)
    width = 0.35  # Width of each bar

    # Create plot
    fig, ax = plt.subplots(figsize=(14, 8))

    # Plot bars for each quantization type
    for i, quant in enumerate(quant_types):
        quant_data = df[df['Quantization'] == quant]
        # Ensure data is in correct order
        quant_data = quant_data.set_index('Model').reindex(models).reset_index()
        
        bars = ax.bar(x + i*width - width/2, quant_data['Accuracy'], width,
                     label=quant, color=palette[quant], edgecolor='black')
        
        # Add reasoning model indicators
        for j, model in enumerate(models):
            if model in REASONING_MODELS:
                bars[j].set_edgecolor('red')
                bars[j].set_hatch('///')

    # Add value labels
    # for i, quant in enumerate(quant_types):
    #     quant_data = df[df['Quantization'] == quant]
    #     quant_data = quant_data.set_index('Model').reindex(models).reset_index()
    #     for j in range(n_models):
    #         height = quant_data.loc[j, 'Accuracy']
    #         ax.text(x[j] + i*width - width/2, height + 0.01,
    #                 f'{height:.2f}', ha='center', va='bottom', fontsize=9)

    # Custom legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=palette["Quantized"], label='Quantized'),
        Patch(facecolor=palette["Concrete"], label='Concrete'),
        Patch(facecolor='white', edgecolor='red', hatch='///', label='Reasoning Model'),
        Patch(facecolor='white', edgecolor='black', label='Non-Reasoning Model')
    ]

    ax.set_title(f'{prediction_type.capitalize()} Prediction Accuracy by Model and Quantization Type', 
                 pad=20, fontsize=14)
    ax.set_xlabel('Model', labelpad=10)
    ax.set_ylabel('Accuracy', labelpad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    ax.legend(handles=legend_elements, bbox_to_anchor=(1.02, 1), loc='upper left')

    plt.tight_layout()
    plt.savefig(f'{prediction_type}_prediction_accuracy_comparison.png', dpi=300, bbox_inches='tight')
    plt.show()

# Generate input prediction plot
plot_prediction_accuracy(
    "/home/XXX/CodeSemantic/CodeSemantic/input_Accuracy_Results/input_python_results.jsonl",
    "input"
)

# Generate output prediction plot
plot_prediction_accuracy(
    "/home/XXX/CodeSemantic/CodeSemantic/output_Accuracy_Results/output_python_results.jsonl",
    "output"
)