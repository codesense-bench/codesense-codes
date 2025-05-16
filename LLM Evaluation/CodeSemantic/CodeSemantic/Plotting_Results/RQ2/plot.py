import json
import matplotlib.pyplot as plt
import numpy as np


data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/block_Accuracy_Results/block_python_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))


cot_yes_data = [d for d in data if d.get("CoT") == "no" and d.get("shot") == 0]


#quantized_yes = [d for d in cot_yes_data if d.get("quantization") == "yes"]
quantized_no = [d for d in cot_yes_data if d.get("quantization") == "no"]


def plot_block_accuracy(data, quantization_type):
    REASONING_MODELS = {
        "DeepSeek-R1-Distill-Qwen-7B",
        "DeepSeek-R1-Distill-Llama-8B",
        "DeepSeek-R1-Distill-Qwen-14B",
        "granite-3.2-8b-instruct",
        "granite-3.2-8b-instruct-preview",
    }
    
    models = []
    block1_acc = []
    block2_acc = []
    block3_acc = []
    is_reasoning = []
    
    for entry in data:
        model_name = entry["Model"]
        models.append(model_name)
        block1_acc.append(entry["block_accuracy"]["1"]["accuracy"])
        block2_acc.append(entry["block_accuracy"]["2"]["accuracy"])
        block3_acc.append(entry["block_accuracy"]["3"]["accuracy"])
        is_reasoning.append(model_name in REASONING_MODELS)
    

    x = np.arange(len(models))
    width = 0.25
    fig, ax = plt.subplots(figsize=(12, 6))
    

    block_colors = {
        'Block 1': '#1f77b4',  # Blue
        'Block 2': '#ff7f0e',  # Orange
        'Block 3': '#2ca02c'   # Green
    }
    

    rects1 = []
    rects2 = []
    rects3 = []
    
    for i, reasoning in enumerate(is_reasoning):

        hatch = '///' if reasoning else None
        
        rects1.append(ax.bar(x[i] - width, block1_acc[i], width, 
                          color=block_colors['Block 1'], 
                          hatch=hatch, edgecolor='black')[0])
        rects2.append(ax.bar(x[i], block2_acc[i], width, 
                          color=block_colors['Block 2'], 
                          hatch=hatch, edgecolor='black')[0])
        rects3.append(ax.bar(x[i] + width, block3_acc[i], width, 
                          color=block_colors['Block 3'], 
                          hatch=hatch, edgecolor='black')[0])
    

    rects1[0].set_label('Block 1')
    rects2[0].set_label('Block 2')
    rects3[0].set_label('Block 3')
    

    # for rects, acc_values in zip([rects1, rects2, rects3], [block1_acc, block2_acc, block3_acc]):
    #     for rect, acc in zip(rects, acc_values):
    #         height = rect.get_height()
    #         ax.text(rect.get_x() + rect.get_width()/2., height,
    #                 f'{acc:.2f}', ha='center', va='bottom', fontsize=8)
    

    from matplotlib.patches import Patch
    

    legend_elements = [
        Patch(facecolor=block_colors['Block 1'], edgecolor='black', label='Block 1'),
        Patch(facecolor=block_colors['Block 2'], edgecolor='black', label='Block 2'),
        Patch(facecolor=block_colors['Block 3'], edgecolor='black', label='Block 3'),
        Patch(facecolor='white', edgecolor='black', hatch='///', label='Reasoning Model'),
        Patch(facecolor='white', edgecolor='black', hatch=None, label='Non-Reasoning Model')
    ]
    
    ax.legend(handles=legend_elements, loc='upper right', ncol=2)
    

    ax.set_xticks(x)
    ax.set_xticklabels(models, rotation=45, ha="right", fontsize=9)
    plt.subplots_adjust(bottom=0.3)
    
    if quantization_type == "no":
        quantization_type = "Concrete Prediction"
        
    print(quantization_type)

    #ax.set_ylabel("Accuracy", fontsize=10)
    #ax.set_title(f"Block Accuracy ({quantization_type})", fontsize=12, pad=20)
    ax.set_ylim(0, 1)
    ax.grid(axis='y', linestyle='--', alpha=0.3)
    

    filename = f"Zero-Shot block_accuracy_quantization_{quantization_type}.png"
    plt.savefig(filename, dpi=300, bbox_inches="tight")
    print(f"Saved figure as {filename}")
    plt.close()
    
#plot_block_accuracy(quantized_yes, "yes")
plot_block_accuracy(quantized_no, "no")