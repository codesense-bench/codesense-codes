#%%
import jsonlines
import os
import tqdm

result_files = list(sorted(os.listdir("profile_c_results")))
datas = []
for fname in tqdm.tqdm(result_files):
    with jsonlines.open(os.path.join("profile_c_results", fname)) as reader:
        for example in reader:
            text = ""
            text += fname + "\n"
            text += os.path.basename(example["fpath"]) + "\n"
            for branch in example["result"]:
                text += " ".join(("\t", "*", branch["type"] + ":", str(branch["condition"]))) + "\n"
            datas.append(text)

#%%
import random
random.seed(0)
for d in random.sample(datas, 100):
    print(d)
