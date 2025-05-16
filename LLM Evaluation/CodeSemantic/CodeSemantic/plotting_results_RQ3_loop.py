import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import pandas as pd
import os

def plot_iteration_body_accuracy(results_file='Results/loop_predictions.json'):
    """Plot iteration vs body prediction accuracy comparison for models."""
    # Load data
    with open(results_file) as f:
        results = json.load(f)

    # Define reasoning models (if needed)
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
            for lang, components in lang_data.items():
                data.append({
                    'Model': model,
                    'Language': lang,
                    'Component': 'Iteration',
                    'Accuracy': components['iteration']['overall_accuracy'],
                    'Model Type': 'Reasoning' if model in reasoning_models else 'Baseline'
                })
                data.append({
                    'Model': model,
                    'Language': lang,
                    'Component': 'Body',
                    'Accuracy': components['body']['overall_accuracy'],
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
            
        # Sort models by iteration accuracy
        model_order = lang_df[lang_df['Component'] == 'Iteration']\
            .groupby('Model')['Accuracy'].mean()\
            .sort_values(ascending=False).index
        
        # Create a color palette
        palette = {'Iteration': '#4C72B0', 'Body': '#DD8452'}  # Blue for iteration, orange for body
        
        # Plot
        ax = sns.barplot(
            data=lang_df,
            x='Model',
            y='Accuracy',
            hue='Component',
            order=model_order,
            palette=palette
        )
        
        # Add edge colors to distinguish reasoning models
        for i, bar in enumerate(ax.patches):
            model_name = model_order[i % (len(model_order))]
            is_reasoning = model_name in reasoning_models
            bar.set_edgecolor('red' if is_reasoning else 'white')
            bar.set_linewidth(2 if is_reasoning else 1)
        
        # Add value labels
        for bar in ax.patches:
            height = bar.get_height()
            if height > 0.01:
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
            mpatches.Patch(facecolor='#4C72B0', label='Iteration'),
            mpatches.Patch(facecolor='#DD8452', label='Body'),
            mpatches.Patch(facecolor='white', edgecolor='red', linewidth=2, label='Reasoning Model')
        ]
        plt.legend(
            handles=handles,
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            fontsize=10
        )

        plt.title(f'Iteration vs Body value Prediction Accuracy - {language.title()}', fontsize=14, pad=20)
        plt.ylim(0, min(1.0, lang_df['Accuracy'].max() * 1.2))
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Save plot
        filename = f'Results/iteration_body_accuracy_{language.lower()}.png'
        plt.savefig(filename, bbox_inches='tight', dpi=300)
        plt.close()
        print(f"Saved plot to {filename}")

    # Generate plots for all languages in the data
    for lang in df['Language'].unique():
        plot_language_comparison(lang)
    
    return df

def main():
    """Main function to execute the plotting."""
    print("Generating iteration vs body prediction accuracy plots...")
    df = plot_iteration_body_accuracy()
    print("Done! Check the 'Results' directory for plots.")

if __name__ == '__main__':
    main()