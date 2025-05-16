import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import pandas as pd
import os

def plot_alias_prediction_accuracy(results_file='Results/alias_predictions.json'):
    """Plot alias prediction accuracy with reasoning model highlighting."""
    # Load data
    with open(results_file) as f:
        results = json.load(f)

    # Define reasoning models (customize this set as needed)
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
            for lang, acc_data in lang_data.items():
                data.append({
                    'Model': model,
                    'Language': lang,
                    'Accuracy': acc_data['overall_accuracy'],
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
        plt.figure(figsize=(10, 6), dpi=120)
        lang_df = df[df['Language'] == language.lower()].copy()
        
        if lang_df.empty:
            print(f"No data available for {language}")
            return
            
        # Sort models by accuracy
        lang_df = lang_df.sort_values('Accuracy', ascending=False)
        
        # Plot
        ax = sns.barplot(
            data=lang_df,
            x='Model',
            y='Accuracy',
            color='#4C72B0'  # Base color for all bars
        )
        
        # Highlight reasoning models with red edges
        for i, bar in enumerate(ax.patches):
            model_name = lang_df.iloc[i]['Model']
            if model_name in reasoning_models:
                bar.set_edgecolor('red')
                bar.set_linewidth(2)
            else:
                bar.set_edgecolor('white')
                bar.set_linewidth(1)
        
        # Add value labels
        for bar in ax.patches:
            height = bar.get_height()
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height + 0.01,
                f'{height:.2f}',
                ha='center',
                va='bottom',
                fontsize=10
            )

        # Custom legend
        handles = [
            mpatches.Patch(facecolor='#4C72B0', label='Alias Prediction'),
            mpatches.Patch(facecolor='white', edgecolor='red', linewidth=2, label='Reasoning Model')
        ]
        plt.legend(
            handles=handles,
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            fontsize=10
        )

        plt.title(f'Alias Prediction Accuracy - {language.upper()}', fontsize=14, pad=20)
        plt.ylim(0, min(1.0, lang_df['Accuracy'].max() * 1.2))
        plt.xticks(rotation=45, ha='right')
        plt.ylabel('Accuracy')
        plt.tight_layout()
        
        # Save plot
        filename = f'Results/alias_prediction_accuracy_{language.lower()}.png'
        plt.savefig(filename, bbox_inches='tight', dpi=300)
        plt.close()
        print(f"Saved plot to {filename}")

    # Generate plots for all languages in the data
    for lang in df['Language'].unique():
        plot_language_comparison(lang)
    
    return df

def main():
    """Main function to execute the plotting."""
    print("Generating alias prediction accuracy plots with reasoning highlights...")
    df = plot_alias_prediction_accuracy()
    print("Done! Check the 'Results' directory for plots.")

if __name__ == '__main__':
    main()