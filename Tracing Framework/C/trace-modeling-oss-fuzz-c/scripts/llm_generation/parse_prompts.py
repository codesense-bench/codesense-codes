import re
from pathlib import Path
import json

def parse_prompt_file(fpath):
    with open(fpath) as f:
        prompt = f.read()
    
    examples = re.findall(r"Problem:\n```\n(.*?)\n```\n\nSolution:\n```\n(.*?)\n```", prompt, flags=re.DOTALL)
    examples = [{"signature": a, "harness": b} for a, b in examples]

    return examples

if __name__ == "__main__":
    files = list(Path("/home/XXX/Code/trace-modeling/llm-fuzz/oss-fuzz-llm-targets-public").glob(f"*/prompts.txt"))
    all_incontext_examples = []
    projects_signatures = set()
    for fpath in files:
        fname = fpath.parent.name.split(".")[0]
        project, _, function = fname.rpartition("-")
        incontext_examples = parse_prompt_file(fpath)
        for example in incontext_examples:
            if (project, example["signature"]) in projects_signatures:
                continue
            else:
                example["project"] = project
                example["function"] = function
                all_incontext_examples.append(example)
                projects_signatures.add((project, example["signature"]))
    with open("/home/XXX/Code/trace-modeling/oss-fuzz-c/code/incontext_examples.jsonl", "w") as f:
        for d in all_incontext_examples:
            f.write(json.dumps(d) + "\n")
    # TODO: looks like the same 2 examples are used for many of the projects. This might mean we can simplify our prompting script. Review the article.
