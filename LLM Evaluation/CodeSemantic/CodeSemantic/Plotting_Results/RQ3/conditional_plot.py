import json
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import Patch


REASONING_MODELS = {
    "DeepSeek-R1-Distill-Qwen-7B",
    "DeepSeek-R1-Distill-Llama-8B",
    "DeepSeek-R1-Distill-Qwen-14B",
    "granite-3.2-8b-instruct",
    "granite-3.2-8b-instruct-preview",
}


data = []
with open("/home/XXX/CodeSemantic/CodeSemantic/conditional_Accuracy_Results/conditional_python_results.jsonl", "r") as f:
    for line in f:
        data.append(json.loads(line))


alias_data = []
for record in data:

    if record.get("quantization") == "no" and record.get("shot") == 0:
        alias_data.append({
            "Model": record["Model"],
            "Accuracy": record["accuracy"],
            "IsReasoning": record["Model"] in REASONING_MODELS
        })

df = pd.DataFrame(alias_data)


models_sorted = sorted(df['Model'].unique(), key=lambda x: x in REASONING_MODELS)
df['Model'] = pd.Categorical(df['Model'], categories=models_sorted, ordered=True)
df = df.sort_values('Model')


plt.figure(figsize=(12, 6))
ax = plt.gca()


palette = {
    True: "#4e79a7",  
    False: "#f28e2b"  
}


bars = ax.bar(
    x=range(len(df)),
    height=df['Accuracy'],
    color=[palette[x] for x in df['IsReasoning']],
    edgecolor=['red' if x else 'black' for x in df['IsReasoning']],
    hatch=['///' if x else None for x in df['IsReasoning']]
)


# for bar in bars:
#     height = bar.get_height()
#     ax.text(bar.get_x() + bar.get_width()/2, height + 0.01,
#             f'{height:.2f}', ha='center', va='bottom', fontsize=9)


legend_elements = [
    Patch(facecolor=palette[True], edgecolor='red', hatch='///', 
          label='Reasoning Models'),
    Patch(facecolor=palette[False], edgecolor='black', 
          label='Non-Reasoning Models')
]


# ax.set_title('Condition Prediction Accuracy', pad=20, fontsize=14)
# ax.set_xlabel('Model', labelpad=10)
ax.set_ylabel('Accuracy', labelpad=10)
ax.set_xticks(range(len(df)))
ax.set_xticklabels(df['Model'], rotation=45, ha='right')
ax.set_ylim(0, 1.1)
ax.grid(axis='y', linestyle='--', alpha=0.3)
ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.95, 0.95), framealpha=1)

plt.tight_layout()
plt.savefig('condition_accuracy.png', dpi=300, bbox_inches='tight')
plt.show()
