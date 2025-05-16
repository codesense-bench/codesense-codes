import jsonlines
from lxml import etree
import argparse
from pathlib import Path

def serialize_step(node):
    variables = []
    for child in node:
        if child.tag == "variable":
            variables.append({"text": child.text, "attr": child.attr})
        else:
            raise NotImplementedError(child.tag)
    return {"type": node.tag,"variables": variables,"attr": node.attr}

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--in_file", type=Path)
    p.add_argument("--out_dir", type=Path)
    args = p.parse_args()

    in_file = args.in_file
    assert in_file.is_file()
    out_dir = args.out_dir
    assert out_dir.is_dir()

    out_file = out_dir / (in_file.parent.parent.name + "_" + in_file.parent.name + ".jsonl")
    with jsonlines.open(out_file, "w") as w:
        for i, (event, element) in enumerate(etree.iterparse(in_file, tag="call")):
            steps = []
            for child in element:
                if child.tag == "call":
                    pass
                elif child.tag == "tracepoint":
                    steps.append(serialize_step(child))
                elif child.tag == "step":
                    steps.append(serialize_step(child))
                else:
                    raise NotImplementedError(child.tag)
            w.write({"idx": i, "steps": steps, "attr": element.attr})
