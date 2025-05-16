import json
import matplotlib.pyplot as plt
import numpy as np

def plot_models_vs_shots(json_file_path, save_path=None):
    with open(json_file_path) as f:
        data = json.load(f)
    
    models = []
    shot_0_acc = []
    shot_1_acc = []
    shot_2_acc = []
    shot_3_acc = []
    
    for model_name, model_data in data.items():
        models.append(model_name)
        statement_data = model_data['pt0']['python']['statement']
        
        shot_0_acc.append(statement_data['shot0']['overall_accuracy'])
        
        shot_1_acc.append(
            statement_data['shot1']['CoT_no']['Incontext_different']['overall_accuracy']
        )

        shot_2_acc.append(
            statement_data['shot2']['CoT_no']['Incontext_different']['overall_accuracy']
        )

        shot_3_acc.append(
            statement_data['shot3']['CoT_no']['Incontext_different']['overall_accuracy']
        )
    
    shot_0_acc = [x * 100 for x in shot_0_acc]
    shot_1_acc = [x * 100 for x in shot_1_acc]
    shot_2_acc = [x * 100 for x in shot_2_acc]
    shot_3_acc = [x * 100 for x in shot_3_acc]
    
    x = np.arange(len(models))  
    width = 0.2  # Adjusted width to fit four bars
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    rects1 = ax.bar(x - 1.5 * width, shot_0_acc, width, label='0-shot', color='#1f77b4')
    rects2 = ax.bar(x - 0.5 * width, shot_1_acc, width, label='1-shot', color='#ff7f0e')
    rects3 = ax.bar(x + 0.5 * width, shot_2_acc, width, label='2-shot', color='#2ca02c')
    rects4 = ax.bar(x + 1.5 * width, shot_3_acc, width, label='3-shot', color='#d62728')
    
    ax.set_ylabel('Overall Accuracy (%)')
    ax.set_title('Model Performance by Number of Shots')
    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha='right')
    ax.legend()
    
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.show()
    
def plot_shot_comparison(json_file_path, save_path=None):
    """
    Generate two separate comparison plots:
    1. CoT vs Non-CoT performance (averaging shot counts)
    2. 1-shot vs 2-shot vs 3-shot performance (averaging CoT settings)
    """
    with open(json_file_path) as f:
        data = json.load(f)
    
    models = list(data.keys())
    n_models = len(models)
    
    # Prepare data for both plots
    cot_yes_same, cot_yes_diff = [], []
    cot_no_same, cot_no_diff = [], []
    shot1_cot, shot1_no_cot = [], []
    shot2_cot, shot2_no_cot = [], []
    shot3_cot, shot3_no_cot = [], []
    
    for model_name in models:
        model_data = data[model_name]['pt0']['python']['statement']
        
        # Data for CoT comparison (average across shots)
        cot_yes_same.append(np.mean([
            model_data['shot1']['CoT_yes']['Incontext_same']['overall_accuracy'],
            model_data['shot2']['CoT_yes']['Incontext_same']['overall_accuracy'],
            model_data['shot3']['CoT_yes']['Incontext_same']['overall_accuracy']
        ]) * 100)
        cot_yes_diff.append(np.mean([
            model_data['shot1']['CoT_yes']['Incontext_different']['overall_accuracy'],
            model_data['shot2']['CoT_yes']['Incontext_different']['overall_accuracy'],
            model_data['shot3']['CoT_yes']['Incontext_different']['overall_accuracy']
        ]) * 100)
        cot_no_same.append(np.mean([
            model_data['shot1']['CoT_no']['Incontext_same']['overall_accuracy'],
            model_data['shot2']['CoT_no']['Incontext_same']['overall_accuracy'],
            model_data['shot3']['CoT_no']['Incontext_same']['overall_accuracy']
        ]) * 100)
        cot_no_diff.append(np.mean([
            model_data['shot1']['CoT_no']['Incontext_different']['overall_accuracy'],
            model_data['shot2']['CoT_no']['Incontext_different']['overall_accuracy'],
            model_data['shot3']['CoT_no']['Incontext_different']['overall_accuracy']
        ]) * 100)
        
        # Data for shot comparison (average across CoT)
        shot1_cot.append(np.mean([
            model_data['shot1']['CoT_yes']['Incontext_same']['overall_accuracy'],
            model_data['shot1']['CoT_yes']['Incontext_different']['overall_accuracy']
        ]) * 100)
        shot1_no_cot.append(np.mean([
            model_data['shot1']['CoT_no']['Incontext_same']['overall_accuracy'],
            model_data['shot1']['CoT_no']['Incontext_different']['overall_accuracy']
        ]) * 100)
        shot2_cot.append(np.mean([
            model_data['shot2']['CoT_yes']['Incontext_same']['overall_accuracy'],
            model_data['shot2']['CoT_yes']['Incontext_different']['overall_accuracy']
        ]) * 100)
        shot2_no_cot.append(np.mean([
            model_data['shot2']['CoT_no']['Incontext_same']['overall_accuracy'],
            model_data['shot2']['CoT_no']['Incontext_different']['overall_accuracy']
        ]) * 100)
        shot3_cot.append(np.mean([
            model_data['shot3']['CoT_yes']['Incontext_same']['overall_accuracy'],
            model_data['shot3']['CoT_yes']['Incontext_different']['overall_accuracy']
        ]) * 100)
        shot3_no_cot.append(np.mean([
            model_data['shot3']['CoT_no']['Incontext_same']['overall_accuracy'],
            model_data['shot3']['CoT_no']['Incontext_different']['overall_accuracy']
        ]) * 100)

    # Figure 1: CoT Comparison (4 bars per model)
    plt.figure(figsize=(12, 6))
    x = np.arange(n_models)
    width = 0.18  # Width of each bar
    gap = 0.02    # Gap between bars
    
    # Calculate positions for 4 bars centered around each x value
    pos1 = x - (1.5*width + 1.5*gap)
    pos2 = x - (0.5*width + 0.5*gap)
    pos3 = x + (0.5*width + 0.5*gap)
    pos4 = x + (1.5*width + 1.5*gap)
    
    plt.bar(pos1, cot_yes_same, width, label='With CoT - Same Context', color='#1f77b4')
    plt.bar(pos2, cot_yes_diff, width, label='With CoT - Different Context', color='#ff7f0e')
    plt.bar(pos3, cot_no_same, width, label='Without CoT - Same Context', color='#aec7e8')
    plt.bar(pos4, cot_no_diff, width, label='Without CoT - Different Context', color='#ffbb78')
    
    plt.ylabel('Accuracy (%)')
    plt.title('Chain-of-Thought (CoT) Performance Comparison\n(Averaged Across Shot Counts)')
    plt.xticks(x, models, rotation=45, ha='right')  # Added ha='right' for better label alignment
    plt.ylim(0, 100)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    
    if save_path:
        plt.savefig(f"{save_path}_cot_comparison.png", dpi=300, bbox_inches='tight')
    plt.show()

    # Figure 2: Shot Count Comparison (6 bars per model)
    plt.figure(figsize=(14, 6))
    x = np.arange(n_models)
    width = 0.12  # Narrower width to fit more bars
    gap = 0.01    # Smaller gap between bars
    
    # Calculate positions for 6 bars centered around each x value
    pos1 = x - (2.5*width + 2.5*gap)
    pos2 = x - (1.5*width + 1.5*gap)
    pos3 = x - (0.5*width + 0.5*gap)
    pos4 = x + (0.5*width + 0.5*gap)
    pos5 = x + (1.5*width + 1.5*gap)
    pos6 = x + (2.5*width + 2.5*gap)
    
    plt.bar(pos1, shot1_cot, width, label='1-shot - With CoT', color='#1f77b4')
    plt.bar(pos2, shot1_no_cot, width, label='1-shot - Without CoT', color='#aec7e8')
    plt.bar(pos3, shot2_cot, width, label='2-shot - With CoT', color='#ff7f0e')
    plt.bar(pos4, shot2_no_cot, width, label='2-shot - Without CoT', color='#ffbb78')
    plt.bar(pos5, shot3_cot, width, label='3-shot - With CoT', color='#2ca02c')
    plt.bar(pos6, shot3_no_cot, width, label='3-shot - Without CoT', color='#98df8a')
    
    plt.ylabel('Accuracy (%)')
    plt.title('Shot Count Performance Comparison\n(Averaged Across Context Settings)')
    plt.xticks(x, models, rotation=45, ha='right')  # Added ha='right' for better label alignment
    plt.ylim(0, 100)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    
    if save_path:
        plt.savefig(f"{save_path}_shot_comparison.png", dpi=300, bbox_inches='tight')
    plt.show()
def plot_type_accuracy_comparison(json_file_path, save_path=None):
    """
    Plot type accuracy comparison for 0-shot, 1-shot and 2-shot with CoT_yes and CoT_no.
    Handles single or multiple models correctly.
    """
    with open(json_file_path) as f:
        data = json.load(f)
    
    models = list(data.keys())
    statement_types = ["Assignment", "Branch", "API", "Arithmetic Assignment", "Constant Assignment"]
    
    # Determine grid layout
    ncols = 2
    nrows = (len(models) + ncols - 1) // ncols
    
    # Adjust figure size based on number of rows
    fig_height = 6 * nrows
    fig, axes = plt.subplots(nrows, ncols, figsize=(18, fig_height))
    
    # If only one model, wrap axes in a list
    if len(models) == 1:
        axes = np.array([[axes]])
    elif nrows == 1:
        axes = axes.reshape(1, -1)
    
    fig.suptitle('Type Accuracy Comparison (Including Zero-shot)', y=1.02, fontsize=14)
    
    for i, model_name in enumerate(models):
        row = i // ncols
        col = i % ncols
        ax = axes[row, col]
        
        model_data = data[model_name]
        statement_data = model_data['pt0']['python']['statement']
        
        # Get the data for each configuration
        zero_shot = statement_data['shot0']['type_accuracy']
        cot_yes_1shot = statement_data['shot1']['CoT_yes']['Incontext_different']['type_accuracy']
        cot_no_1shot = statement_data['shot1']['CoT_no']['Incontext_different']['type_accuracy']
        cot_yes_2shot = statement_data['shot2']['CoT_yes']['Incontext_different']['type_accuracy']
        cot_no_2shot = statement_data['shot2']['CoT_no']['Incontext_different']['type_accuracy']
        
        # Convert to percentages
        zero_shot = [zero_shot[typ] * 100 for typ in statement_types]
        cot_yes_1shot = [cot_yes_1shot[typ] * 100 for typ in statement_types]
        cot_no_1shot = [cot_no_1shot[typ] * 100 for typ in statement_types]
        cot_yes_2shot = [cot_yes_2shot[typ] * 100 for typ in statement_types]
        cot_no_2shot = [cot_no_2shot[typ] * 100 for typ in statement_types]
        
        x = np.arange(len(statement_types))
        width = 0.15
        
        bars = []
        bars.append(ax.bar(x - 2*width, zero_shot, width, label='0-shot', color='#7f7f7f'))
        bars.append(ax.bar(x - width, cot_yes_1shot, width, label='1-shot CoT=yes', color='#1f77b4'))
        bars.append(ax.bar(x, cot_no_1shot, width, label='1-shot CoT=no', color='#aec7e8'))
        bars.append(ax.bar(x + width, cot_yes_2shot, width, label='2-shot CoT=yes', color='#ff7f0e'))
        bars.append(ax.bar(x + 2*width, cot_no_2shot, width, label='2-shot CoT=no', color='#ffbb78'))
        
        ax.set_title(model_name, pad=10)
        ax.set_xticks(x)
        ax.set_xticklabels(statement_types, rotation=45, ha='right')
        ax.set_ylabel('Accuracy (%)')
        ax.set_ylim(0, 100)
        ax.grid(True, axis='y', linestyle='--', alpha=0.7)
        
        # Add value labels on top of bars if there's space
        # if len(models) <= 4:
        #     for bar_group in bars:
        #         for bar in bar_group:
        #             height = bar.get_height()
        #             ax.annotate(f'{height:.1f}',
        #                         xy=(bar.get_x() + bar.get_width()/2, height),
        #                         xytext=(0, 3),
        #                         textcoords="offset points",
        #                         ha='center', va='bottom', fontsize=8)
    
    # Hide any empty subplots
    for i in range(len(models), nrows * ncols):
        row = i // ncols
        col = i % ncols
        axes[row, col].axis('off')
    
    # Create a unified legend
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', ncol=5,bbox_to_anchor=(0.5, 1.05))
    
    plt.tight_layout(pad=3.0)
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.show()


def main():
    plot_models_vs_shots('statement_predictions.json', 'models_vs_shots.png')
    plot_shot_comparison('statement_predictions.json', save_path='shot_comparison.png')
    plot_type_accuracy_comparison('statement_predictions.json', 'type_accuracy_comparison.png')

    

if __name__ == "__main__":
    main()
