import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches  # Add this import
import seaborn as sns
import pandas as pd
import os

def plot_io_prediction_accuracy(results_file='Results/input_output_predictions.json'):
    """Plot input/output prediction accuracy comparison for models."""
    # Load data
    with open(results_file) as f:
        results = json.load(f)

    # Define reasoning models (exact names as in JSON keys)
    reasoning_models = {
        "DeepSeek-R1-Distill-Qwen-7B",
        "DeepSeek-R1-Distill-Llama-8B",
        "DeepSeek-R1-Distill-Qwen-14B",
        "granite-3.2-8b-instruct",
        "granite-3.2-8b-instruct-preview",
    }

    # Prepare data
    data = []
    for model, pt_data in results.items():
        for pt, lang_data in pt_data.items():
            for lang, io_data in lang_data.items():
                data.append({
                    'Model': model,
                    'Language': lang,
                    'Prediction Type': 'Output',
                    'Accuracy': io_data['output']['overall_accuracy'],
                    'Model Type': 'Reasoning' if model in reasoning_models else 'Baseline'
                })
                data.append({
                    'Model': model,
                    'Language': lang,
                    'Prediction Type': 'Input',
                    'Accuracy': io_data['input']['overall_accuracy'],
                    'Model Type': 'Reasoning' if model in reasoning_models else 'Baseline'
                })

    df = pd.DataFrame(data)
    
    # Set visual style
    sns.set_theme(style="whitegrid")
    plt.rcParams['font.size'] = 12
    
    # Create directory if needed
    os.makedirs('Results', exist_ok=True)

    def plot_language_comparison(language):
        """Plot comparison for a specific language."""
        plt.figure(figsize=(14, 6), dpi=120)
        lang_df = df[df['Language'] == language.lower()].copy()
        
        if lang_df.empty:
            print(f"No data available for {language}")
            return
            
        # Sort models by output accuracy
        model_order = lang_df[lang_df['Prediction Type'] == 'Output']\
            .groupby('Model')['Accuracy'].mean()\
            .sort_values(ascending=False).index
        
        # Create a color palette with edge colors for reasoning models
        palette = {'Output': '#4C72B0', 'Input': '#DD8452'}  # Blue for output, orange for input
        edge_colors = []
        
        # Plot
        ax = sns.barplot(
            data=lang_df,
            x='Model',
            y='Accuracy',
            hue='Prediction Type',
            order=model_order,
            palette=palette
        )
        
        # Add edge colors to distinguish reasoning models
        for i, bar in enumerate(ax.patches):
            model_name = model_order[i % (len(model_order))]  # Get model name for this bar
            is_reasoning = model_name in reasoning_models
            bar.set_edgecolor('red' if is_reasoning else 'white')  # Red edge for reasoning models
            bar.set_linewidth(2 if is_reasoning else 1)  # Thicker edge for reasoning models
        
        # Add value labels
        for bar in ax.patches:
            height = bar.get_height()
            if height > 0.01:  # Only label bars with height > 1%
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    height + 0.01,
                    f'{height:.2f}',
                    ha='center',
                    va='bottom',
                    fontsize=9
                )

        # Custom legend
        handles = [
            mpatches.Patch(facecolor='#4C72B0', label='Output Prediction'),
            mpatches.Patch(facecolor='#DD8452', label='Input Prediction'),
            mpatches.Patch(facecolor='white', edgecolor='red', linewidth=2, label='Reasoning Model')
        ]
        plt.legend(
            handles=handles,
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            fontsize=10
        )

        plt.title(f'Input vs Output Prediction Accuracy - {language.title()}', fontsize=14, pad=20)
        plt.ylim(0, min(1.0, lang_df['Accuracy'].max() * 1.2))
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save plot
        filename = f'Results/io_prediction_accuracy_{language.lower()}.png'
        plt.savefig(filename, bbox_inches='tight', dpi=300)
        plt.close()  # Prevents duplicate displays in notebooks
        print(f"Saved plot to {filename}")

    # Generate plots for all languages in the data
    for lang in df['Language'].unique():
        plot_language_comparison(lang)
    
    return df

def main():
    """Main function to execute the plotting."""
    print("Generating input/output prediction accuracy plots...")
    df = plot_io_prediction_accuracy()
    print("Done! Check the 'Results' directory for plots.")

if __name__ == '__main__':
    main()