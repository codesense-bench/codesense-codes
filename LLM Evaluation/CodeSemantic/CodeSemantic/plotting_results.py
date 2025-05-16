import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import matplotlib.patches as mpatches
import os  # Added for directory creation

def plot_results(results_file='Results/all_results.json'):
    # Load and process data
    with open(results_file) as f:
        results = json.load(f)

    # Define models and settings
    reasoning_models = {
        "DeepSeek-R1-Distill-Qwen-7B",
        "DeepSeek-R1-Distill-Llama-8B",
        "DeepSeek-R1-Distill-Qwen-14B"
    }
    
    # Define the expected statement types based on your JSON
    expected_stmt_types = [
        "API",
        "Arithmetic Assignment",
        "Assignment",
        "Branch",
        "Constant Assignment"
    ]

    # Prepare data
    data = []
    for model, pt_data in results.items():
        for pt, lang_data in pt_data.items():
            for lang, metrics in lang_data.items():
                data.append({
                    'Model': model,
                    'Language': lang,
                    'Accuracy': metrics['overall_accuracy'],
                    'Statement Type': 'Overall',
                    'Count': sum(metrics['type_counts'].values())
                })
                for stmt_type, acc in metrics['type_accuracy'].items():
                    data.append({
                        'Model': model,
                        'Language': lang,
                        'Accuracy': acc,
                        'Statement Type': stmt_type,
                        'Count': metrics['type_counts'][stmt_type]
                    })

    df = pd.DataFrame(data)
    df['Model Type'] = df['Model'].apply(lambda x: 'Reasoning' if x in reasoning_models else 'Baseline')

    # Set visual style
    sns.set_theme(style="whitegrid")
    plt.rcParams['font.size'] = 12
    reasoning_hatch = '///'
    baseline_hatch = ''
    palette = sns.color_palette("husl", len(df['Model'].unique()))

    def plot_statement_accuracy(df, language, title_suffix):
        plt.figure(figsize=(16, 8), dpi=120)
        lang_df = df[(df['Statement Type'] != 'Overall') & 
                    (df['Language'] == language.lower())].copy()
        
        # Ensure we only plot existing statement types
        existing_stmt_types = lang_df['Statement Type'].unique()
        stmt_order = [s for s in expected_stmt_types if s in existing_stmt_types]
        
        if not stmt_order:
            print(f"No statement type data available for {language}")
            return
            
        # Sort models by their overall accuracy
        model_order = lang_df.groupby('Model')['Accuracy'].mean().sort_values(ascending=False).index
        
        # Plot
        ax = sns.barplot(
            data=lang_df,
            x='Statement Type',
            y='Accuracy',
            hue='Model',
            order=stmt_order,
            hue_order=model_order,
            palette=palette
        )

        # Apply hatching for reasoning models
        for i, bar in enumerate(ax.patches):
            model_idx = i // len(stmt_order)
            if model_idx < len(model_order):
                model_name = model_order[model_idx]
                if model_name in reasoning_models:
                    bar.set_hatch(reasoning_hatch)

        # Add value labels
        for bar in ax.patches:
            height = bar.get_height()
            if height > 0.01:
                ax.text(
                    bar.get_x() + bar.get_width()/2.,
                    height + 0.01,
                    f'{height:.2f}',
                    ha='center',
                    va='bottom',
                    fontsize=9
                )

        # Custom legend - FIXED: Changed to legend_handles
        handles = [
            mpatches.Patch(facecolor='gray', hatch=reasoning_hatch, label='Reasoning Model'),
            mpatches.Patch(facecolor='gray', hatch=baseline_hatch, label='Baseline Model')
        ]
        plt.legend(
            handles=handles + ax.legend_.legend_handles,
            bbox_to_anchor=(1.05, 1),
            loc='upper left',
            fontsize=10
        )

        plt.title(f'Statement Type Accuracy - {language} {title_suffix}', fontsize=14, pad=20)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(f'Results/statement_accuracy_{language.lower()}{title_suffix.replace(" ", "_").lower()}.png', 
                   bbox_inches='tight', dpi=300)
        plt.show()

    def plot_overall_accuracy(df, title_suffix=""):
        plt.figure(figsize=(14, 6), dpi=120)
        overall_df = df[df['Statement Type'] == 'Overall'].copy()
        
        if overall_df.empty:
            print("No overall accuracy data available")
            return
            
        # Sort models by accuracy
        model_order = overall_df.groupby('Model')['Accuracy'].mean().sort_values(ascending=False).index
        
        ax = sns.barplot(
            data=overall_df,
            x='Model',
            y='Accuracy',
            hue='Language',
            order=model_order,
            palette=palette
        )

        # Add value labels
        for bar in ax.patches:
            ax.text(
                bar.get_x() + bar.get_width()/2.,
                bar.get_height() + 0.01,
                f'{bar.get_height():.2f}',
                ha='center',
                va='bottom',
                fontsize=9
            )

        plt.title(f'Overall Accuracy by Model {title_suffix}', fontsize=14, pad=20)
        plt.ylim(0, 1)
        plt.xticks(rotation=45, ha='right')
        plt.legend(loc='upper right')
        plt.tight_layout()
        plt.savefig(f'Results/overall_accuracy{title_suffix.replace(" ", "_").lower()}.png', 
                   bbox_inches='tight', dpi=300)
        plt.show()

    # Generate all plots
    print("Generating plots...")
    
    # 1. Overall accuracy (all models)
    plot_overall_accuracy(df)
    
    # 2. Statement accuracy by language (all models)
    plot_statement_accuracy(df, "Python", "(All Models)")
    plot_statement_accuracy(df, "C", "(All Models)")
    
    # 3. Reasoning models only
    reasoning_df = df[df['Model Type'] == 'Reasoning'].copy()
    if not reasoning_df.empty:
        plot_overall_accuracy(reasoning_df, "- Reasoning Models Only")
        plot_statement_accuracy(reasoning_df, "Python", "(Reasoning Models)")
        plot_statement_accuracy(reasoning_df, "C", "(Reasoning Models)")
    else:
        print("Warning: No reasoning models found in the data")
    
    return df  # Return the dataframe for use in comparisons

def plot_model_comparison(df, model1, model2, language="python", save_path="Results/"):
    """
    Generate a bar plot comparing statement accuracy between two specific models.
    
    Args:
        df: DataFrame containing the accuracy data
        model1: First model name (str)
        model2: Second model name (str)
        language: Target language ("python" or "c")
        save_path: Directory to save the plot
    """
    
    expected_stmt_types = [
        "API",
        "Arithmetic Assignment",
        "Assignment",
        "Branch",
        "Constant Assignment"
    ]
    # Filter data for the two models and language
    compare_df = df[
        (df['Model'].isin([model1, model2])) & 
        (df['Language'] == language.lower()) & 
        (df['Statement Type'] != 'Overall')
    ].copy()
    
    if compare_df.empty:
        print(f"No data available for {model1} and {model2} in {language}")
        return
    
    # Get statement types present in the data
    stmt_types = compare_df['Statement Type'].unique()
    stmt_order = [s for s in expected_stmt_types if s in stmt_types]
    
    plt.figure(figsize=(12, 6), dpi=120)
    ax = sns.barplot(
        data=compare_df,
        x='Statement Type',
        y='Accuracy',
        hue='Model',
        order=stmt_order,
        palette=["#4C72B0", "#DD8452"]  # Specific colors for 2 models
    )
    
    # Add value labels
    for bar in ax.patches:
        height = bar.get_height()
        if height > 0.01:
            ax.text(
                bar.get_x() + bar.get_width()/2.,
                height + 0.01,
                f'{height:.2f}',
                ha='center',
                va='bottom',
                fontsize=10
            )
    
    # Customize plot
    plt.title(f'Statement Accuracy Comparison\n{model1} vs {model2} ({language.title()})', pad=15)
    plt.ylabel("Accuracy")
    plt.ylim(0, min(1.0, compare_df['Accuracy'].max() * 1.25))
    plt.xticks(rotation=45, ha='right')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    
    # Save and show
    os.makedirs(save_path, exist_ok=True)
    filename = f"{save_path}comparison_{model1}_vs_{model2}_{language}.png"
    plt.tight_layout()
    plt.savefig(filename, bbox_inches='tight', dpi=300)
    plt.show()
    print(f"Saved comparison plot to {filename}")

if __name__ == '__main__':
    # Get the dataframe from plot_results
    df = plot_results()
    
    # Generate comparison plot
    plot_model_comparison(
        df, 
        model1="Qwen2.5-14B-Instruct-1M", 
        model2="DeepSeek-R1-Distill-Qwen-14B",
        language="python"
    )