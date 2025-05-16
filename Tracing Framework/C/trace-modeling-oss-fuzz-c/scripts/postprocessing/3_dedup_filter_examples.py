#%%
import json
import jsonlines
import itertools
import tqdm

import argparse
parser = argparse.ArgumentParser(description='Description of your program')
parser.add_argument('input_file')
parser.add_argument('output_file')
args = parser.parse_args()

def ambiguate(var):
    if isinstance(var, str):
        # unhandled node type, probably event thread mismatch
        return None
    if var["tag"] == "event-thread-mismatch":
        return {
            "tag": var["tag"],
        }
    if var["tag"] == "exception":
        return {
            "tag": var["tag"],
            "xml": var["xml"].strip(),
        }
    try:
        text = var["text"]
    except KeyError:
        print("unhandled", var)
        return None
    if var["serializer"] == "TOSTRING":
        if "@" in text:
            if text.startswith('\"') and text.endswith('\"'):
                text = text[1:-1]
            text = text[:text.find("@")]
    return {
        "tag": var["tag"],
        "name": var["name"],
        "type": var["type"],
        "source": var["source"],
        "serializer": var["serializer"],
        "text": text,
    }

def make_hash(example):
    variables = []
    for v in example["entry_variables"]:
        if v is None:
            # unhandled node
            return None
        av = ambiguate(v)
        if av is None:
            return None
        variables.append(av)
    return json.dumps({
        "class": example["class"],
        "method": example["method"],
        "start_point": example["start_point"],
        "end_point": example["end_point"],
        "variables": variables
    })

seen_examples = set()

def filter_example(example):
    if example["is_forward"]:
        return "forward"
    # TODO: detect empty function.
    h = make_hash(example)
    if h is None:
        return "failed"
    else:
        if h not in seen_examples:
            seen_examples.add(h)
            return "new"
        else:
            return "duplicated"

how_many_seen = {
    "new": 0,
    "duplicated": 0,
    "forward": 0,
    "failed": 0,
}

limit = False
# limit = True

if limit:
    num_lines = None
else:
    num_lines = 0
    with open(args.input_file) as inf:
        num_lines += sum(1 for _ in inf)
with jsonlines.open(args.input_file) as inf, jsonlines.open(args.output_file, "w") as outf:
    it = inf
    if limit:
        it = itertools.islice(it, 5)
    with tqdm.tqdm(it, total=num_lines, desc="dedup/filtering") as pbar:
        for example in pbar:
            try:
                outcome = filter_example(example)
                how_many_seen[outcome] += 1
                pbar.set_postfix(how_many_seen)
                if outcome == "new":
                    outf.write(example)
            except Exception:
                print("ERROR", json.dumps(example, indent=2))
                raise
        
