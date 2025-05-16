#%%
import pandas as pd
df = pd.read_csv("corpus_list_20230413.csv")
print(df["project"].count(), "project directories,", df["project"].nunique(), "unique")
print("machine contribution:")
print(df.value_counts("machine").to_string(header=False))

#%%
from pathlib import Path
project_dirs = list(Path("build/corpus").glob("*/"))
fuzzer_dirs = list(Path("build/corpus").glob("*/*/"))
corpus_files = list(Path("build/corpus").glob("*/*/*"))
print(len(project_dirs), "project dirs,", len(fuzzer_dirs), "fuzzer dirs,", len(corpus_files), "data files locally")
