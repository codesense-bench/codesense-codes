#%%
import itertools
import jsonlines
import tqdm
import pandas as pd

from class_parser import get_child, get_children, get_method_node

with open("examples_sorted.jsonl") as inf:
    num_lines = sum(1 for _ in inf)

all_rows = []
with jsonlines.open("examples_sorted.jsonl") as inf:
    # inf = itertools.islice(inf, 1000)
    took = 0
    with tqdm.tqdm(inf, initial=took, total=num_lines) as pbar:
        for example in pbar:
            row_info = {}
            
            method_node = get_method_node(example["file_path"], example["class"], example["method"], int(example["attributes"]["location"].split(":")[1]))
            block = get_child(method_node, lambda n: n.type == "block")
            block_stmts = get_children(block, lambda n: n.is_named)
            row_info["num_stmts"] = len(block_stmts)
            row_info["num_chars"] = len(example["code"])
            row_info["class"] = example["class"]
            row_info["method"] = example["method"]

            all_rows.append(row_info)
all_rows = pd.DataFrame(all_rows)
all_rows

#%%
print(all_rows["class"].nunique(), "unique classes and", all_rows["method"].nunique(), "unique methods")

#%%
from matplotlib import pyplot as plt
import seaborn as sns
all_rows["num_stmts"].plot.hist(density=True, alpha=0.5)
sns.kdeplot(data=all_rows, x="num_stmts", ax=plt.gca())
plt.title("number of top-level statements per method")

#%%
all_rows["num_chars"].plot.hist(density=True, alpha=0.5)
sns.kdeplot(data=all_rows, x="num_chars", ax=plt.gca())
plt.title("number of characters per method")

# %%
import numpy as np
f, (ax_box, ax_hist) = plt.subplots(2, sharex=True, gridspec_kw={"height_ratios": (.25, .75)})
 
# assigning a graph to each ax
all_rows["num_stmts"].plot.hist(ax=ax_hist, alpha=0.5, bins=np.arange(0, max(all_rows["num_stmts"])+1, 1.0))
all_rows["num_stmts"].plot.box(ax=ax_box, vert=False, showmeans=True)
ticks = np.arange(max(all_rows["num_stmts"]), max(all_rows["num_stmts"]), 1.0)
# plt.xticks(ticks[::1], ticks[::1])
# sns.histplot(data=all_rows, x="num_stmts", ax=ax_hist)
from matplotlib.ticker import (MultipleLocator, AutoMinorLocator)
ax_hist.set_xlabel("number of statements")
ax_hist.xaxis.set_major_locator(MultipleLocator(5))
ax_hist.xaxis.set_minor_locator(MultipleLocator(1))
 
# Remove x axis name for the boxplot
ax_box.set(xlabel='')

f.suptitle("number of statements in a method")
