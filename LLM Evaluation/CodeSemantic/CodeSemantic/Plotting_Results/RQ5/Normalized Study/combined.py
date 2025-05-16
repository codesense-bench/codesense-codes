import json
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# Reasoning models set
REASONING_MODELS = {
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "granite-3.2-8b-instruct",
    "granite-3.2-8b-instruct-preview",
}

# Paid proprietary models set
PAID_MODELS = {
    "anthropic.claude-3-5-sonnet-20241022-v2:0",
    "gemini-1.5-flash-002",
}

def load_and_filter_results(file_path, language, prediction_type):
    data = []
    with open(file_path, "r") as f:
        for line in f:
            record = json.loads(line)
            # Filter shot=0, Incontext=different, quantization=no
            if record["shot"] == 0 and record["Incontext"] == "different" and record["quantization"] == "no":
                data.append({
                    "Model": record["Model"],
                    "Accuracy": record["accuracy"],
                    "Language": language,
                    "Prediction": prediction_type,
                    "IsReasoning": record["Model"] in REASONING_MODELS,
                    "IsPaid": record["Model"] in PAID_MODELS
                })
    return data

def plot_language_comparison(results, prediction_type):
    df = pd.DataFrame(results)

    # Sort models: Free Non-Reasoning → Paid → Reasoning
    def model_priority(model):
        if model in REASONING_MODELS:
            return (2, model)
        elif model in PAID_MODELS:
            return (1, model)
        else:
            return (0, model)

    models_sorted = sorted(df['Model'].unique(), key=model_priority)
    df['Model'] = pd.Categorical(df['Model'], categories=models_sorted, ordered=True)

    # Plot setup
    languages = df['Language'].unique()
    models = df['Model'].cat.categories
    n_models = len(models)
    n_languages = len(languages)

    x = np.arange(n_models)
    width = 0.2  # Width of each bar

    # Color palette for languages
    palette = {"Python": "#4e79a7", "C": "#f28e2b", "Java": "#76b7b2"}

    fig, ax = plt.subplots(figsize=(14, 8))

    # Plot bars for each language
    for i, lang in enumerate(languages):
        lang_data = df[df['Language'] == lang].set_index('Model').reindex(models).reset_index()

        bars = ax.bar(x + i*width - width, lang_data['Accuracy'], width,
                      label=lang, color=palette[lang], edgecolor='black')

        # Add category indicators (Reasoning / Paid)
        for j, row in lang_data.iterrows():
            if row['IsReasoning']:
                bars[j].set_edgecolor('red')
                bars[j].set_hatch('///')
            elif row['IsPaid']:
                bars[j].set_edgecolor('green')
                bars[j].set_hatch('\\\\\\')

    # Custom legend
    legend_elements = [
        Patch(facecolor=palette["Python"], label='Python'),
        Patch(facecolor=palette["C"], label='C'),
        Patch(facecolor=palette["Java"], label='Java'),
        Patch(facecolor='white', edgecolor='red', hatch='///', label='Reasoning Models'),
        Patch(facecolor='white', edgecolor='green', hatch='\\\\\\', label='Paid Models'),
        Patch(facecolor='white', edgecolor='black', label='Free Non-Reasoning Models')
    ]

    # Labels and titles
    # ax.set_title(f'{prediction_type.capitalize()} Prediction Accuracy across Languages', pad=20, fontsize=14)
    # ax.set_xlabel('Model', labelpad=10)
    ax.set_ylabel('Accuracy', labelpad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right')
    ax.set_ylim(0, 1.1)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.95, 0.95), framealpha=1)

    plt.tight_layout()
    plt.savefig(f'Normalized_{prediction_type}_prediction_language_comparison.png', dpi=300, bbox_inches='tight')
    plt.show()

# --- INPUT Prediction ---
input_results = []
input_results += load_and_filter_results("/home/XXX/CodeSemantic/CodeSemantic/Plotting_Results/RQ5/Normalized Study/input_python_results.jsonl", "Python", "input")
input_results += load_and_filter_results("/home/XXX/CodeSemantic/CodeSemantic/input_Accuracy_Results/input_c_results.jsonl", "C", "input")
input_results += load_and_filter_results("/home/XXX/CodeSemantic/CodeSemantic/input_Accuracy_Results/input_java_results.jsonl", "Java", "input")

plot_language_comparison(input_results, "input")

# --- OUTPUT Prediction ---
output_results = []
output_results += load_and_filter_results("/home/XXX/CodeSemantic/CodeSemantic/Plotting_Results/RQ5/Normalized Study/output_python_results.jsonl", "Python", "output")
output_results += load_and_filter_results("/home/XXX/CodeSemantic/CodeSemantic/output_Accuracy_Results/output_c_results.jsonl", "C", "output")
output_results += load_and_filter_results("/home/XXX/CodeSemantic/CodeSemantic/output_Accuracy_Results/output_java_results.jsonl", "Java", "output")

plot_language_comparison(output_results, "output")
