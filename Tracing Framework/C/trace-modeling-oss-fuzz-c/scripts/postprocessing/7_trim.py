#%%
import jsonlines
import itertools

#%%
import argparse
parser = argparse.ArgumentParser(description='Description of your program')
parser.add_argument('input_file')
parser.add_argument('output_file')
args = parser.parse_args()

#%
from types import SimpleNamespace
args = SimpleNamespace()
args.input_file = "postprocessed/examples_dedup_sort.jsonl"
args.output_file = "postprocessed/examples_dedup_sort_trim.jsonl"

#%%
import tqdm
with open(args.input_file) as inf:
    num_lines = sum(1 for _ in tqdm.tqdm(inf, desc="count lines", leave=False))
with jsonlines.open("postprocessed/examples_dedup_sort.jsonl") as reader, jsonlines.open("postprocessed/examples_dedup_sort_trim.jsonl", "w") as writer:
    for example in tqdm.tqdm(reader, total=num_lines):
        example["lines_covered"] = list(sorted(set(s["relative_lineno"] for s in example["steps"] if "relative_lineno" in s)))
        del example["steps"]
        writer.write(example)