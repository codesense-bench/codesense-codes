"""NOW FOLDED INTO 2_exampleizer.py"""

#%%
import itertools
import re
import jsonlines
import tqdm
import pandas as pd

from class_parser import get_child, get_children, get_method_node

with open("examples_sorted.jsonl") as inf:
    num_lines = sum(1 for _ in inf)

all_rows = []
with jsonlines.open("examples_sorted.jsonl") as inf, jsonlines.open("examples_sorted_clean.jsonl", "w") as outf:
    # inf = itertools.islice(inf, 1000)
    took = 0
    with tqdm.tqdm(inf, initial=took, total=num_lines) as pbar:
        for example in pbar:
            for v in example["entry_variables"]:
                if v["serializer"] == "ARRAY":
                    v["text"] = v["text"].strip()
                if v["serializer"] == "TOSTRING":
                    text = v["text"]
                    if text.startswith('\"') and text.endswith('\"'):
                        # text = text[1:-1]
                        m = re.search(r"@[\da-z]{8}", text)
                        if m is not None:
                            text = text[:m.start()] + text[m.end():]
                    v["text"] = text
            outf.write(example)
