#%%
import jsonlines
import tqdm
import re

from class_parser import get_method_node, is_forward

with open("examples.jsonl") as inf:
    num_lines = sum(1 for _ in inf)

# class tqdmWithOutcomes(tqdm.tqdm):
#     def __init__(self, *args, outcomes=None, **kwargs):
#         self.outcomes = None
#         super().__init__(*args, **kwargs)
#         if outcomes is None:
#             outcomes = set()
#         self.outcomes = {o: 0 for o in outcomes}
    
#     def add_outcome(self, o):
#         self.outcomes[o] += 1
    
#     def display(self, *args, **kwargs):
#         if self.outcomes is not None:
#             self.set_postfix(self.outcomes)
#         super().display(*args, **kwargs)

outcomes = {o: 0 for o in {"success", "skipped", "changed"}}

with jsonlines.open("examples.jsonl") as inf, jsonlines.open("examples_with_forward.jsonl", "w") as outf:
    took = 0
    # for _ in itertools.islice(inf, 44158):
    #     took += 1
    with tqdm.tqdm(inf, initial=took, total=num_lines) as pbar:
        for example in pbar:
            method_node = get_method_node(example["file_path"], example["class"], example["method"], int(example["attributes"]["location"].split(":")[1]))
            if method_node is None:
                outcomes["skipped"] += 1
                continue
            method_code = method_node.text.decode()
            if method_code != example["code"]:
                example["code"] = method_code
                outcomes["changed"] += 1
            example["project"] = re.search(r"oss-fuzz/repos/([^/]+)/", example["file_path"]).group(1)
            example["is_forward"] = is_forward(method_node)
            outf.write(example)
            outcomes["success"] += 1
            pbar.set_postfix(outcomes)
