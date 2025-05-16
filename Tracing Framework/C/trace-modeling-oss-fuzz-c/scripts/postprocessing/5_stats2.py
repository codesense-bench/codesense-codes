#%%
import jsonlines
from collections import defaultdict
import tqdm
from matplotlib import pyplot as plt
import seaborn as sns
import pandas as pd

#%%
import argparse
parser = argparse.ArgumentParser(description='Description of your program')
parser.add_argument('input_file')
args = parser.parse_args()

#%%
with open(args.input_file) as inf:
    num_lines = sum(1 for _ in inf)

with jsonlines.open(args.input_file) as inf:
    project_examples = []
    current_project = None
    projects = defaultdict(int)
    classes = defaultdict(int)
    for example in tqdm.tqdm(inf, total=num_lines, desc="measuring stats"):
        projects[example["project"]] += 1
        classes[example["class"]] += 1

#%%
print("unique projects:", len(projects))
df = pd.DataFrame(projects.items(), columns=["project", "count"]).sort_values("count")
sns.barplot(df, x="project", y="count")
plt.yscale("log")
plt.xticks(rotation=90)
plt.tight_layout()
plt.show()
df.value_counts("project", normalize=True)

#%%
print("unique classes:", len(classes))
df = pd.DataFrame(classes.items(), columns=["class", "count"]).sort_values("count").reset_index(drop=True)
sns.barplot(df, x="class", y="count")
plt.yscale("log")
selected_ticks = df["class"][::len(df)//50]
plt.gca().set_xticks(selected_ticks.index)
plt.gca().set_xticklabels(selected_ticks.tolist(), rotation='vertical')
plt.tight_layout()
plt.show()
df.value_counts("class", normalize=True)
