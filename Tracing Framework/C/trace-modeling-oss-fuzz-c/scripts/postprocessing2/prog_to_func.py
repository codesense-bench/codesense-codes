"""
Convert XML with multiple traces to individual JSONL traces
WIP UNDER CONSTRUCTION: The current version of the script is unstable.

Install dependencies:

git clone https://github.com/bstee615/tree-cutter.git
export PYTHONPATH="$PYTHONPATH:$PWD/tree-cutter" # Eventually we'll make it a pip package :-)

Example usage:

python scripts/postprocessing2/prog_to_func.py trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/log_698.xml trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/src_698.xml output/

Write the code to a file so we can look at it with syntax highlighting:

head -n1 XXX_jsonl/log_698.jsonl | jq -r '.code_processed' > krb5_trace_Fuzz_ndr_exe_698.c
"""

import json
import jsonlines
from lxml import etree
import argparse
from pathlib import Path
from tree_cutter import process


ERROR = "<error>" # TODO: should this be null or error?

def transform(data):
    """Convert obscure symbols documented in var_utils.py to clean variable records."""
    if isinstance(data, dict):
        for k, v in data.items():
            data[k] = transform(v)
        if "@" in data:
            concrete_type = data["@"]
            del data["@"]
            type_category = data["@@"]
            del data["@@"]
            if "type" in data:
                concrete_type_inferred = data["type"]
                del data["type"]
            else:
                concrete_type_inferred = None
            rest_of_data = data
            data = {
                "type_category": type_category,
                "concrete_type": concrete_type_inferred or concrete_type,
            }
            data.update(rest_of_data)
        else:
            del data["@@"]
            # DEBUG: needed in order to handle missing data in struct types.
            # Fixed in latest tracer.
            concrete_type = "STRUCT"
            type_category = "struct"
            concrete_type_inferred = None
            rest_of_data = data
            data = {
                "type_category": type_category,
                "concrete_type": concrete_type_inferred or concrete_type,
                "value": rest_of_data,
            }
    if isinstance(data, list):
        data = [transform(v) for v in data]
    return data

def deserialize_value(value):
    data = json.loads(value.text)
    data = transform(data)
    return data

def serialize_tracepoint(node):
    variables = {}
    for child in node:
        if child.tag in ["variable", "return-value"]:
            # TODO: filter out uninitialized values
            value = next((c for c in child if c.tag == "value"), None)
            if value is not None:
                try:
                    value_data = deserialize_value(value)
                except Exception as ex:
                    print(f"Error converting value to JSON: {ex}\n{etree.tostring(child).decode()}")
                    raise
                variables[child.attrib.get("name", "return_value")] = value_data
        else:
            raise NotImplementedError(child.tag)
    attributes = dict(node.attrib)
    # del attributes["func_name"]
    # del attributes["func_line"]
    # del attributes["filepath"]
    return {
        "type": node.tag,
        "attr": attributes,
        "variables": variables,
    }

def parse(text):
    from tree_sitter_languages import get_parser
    parser = get_parser("c")
    tree = parser.parse(text.encode())

    functions = {}
    queue = [tree.root_node]
    while len(queue) > 0:
        node = queue.pop(0)
        if node.type == "function_definition":
            function_name = node.child_by_field_name("identifier")
            function_code = node.text.decode()
            functions[function_name] = function_code
        queue.extend(node.children)
    return functions

def get_file_code(files, fpath_stub):
    for fpath, code in files.items():
        if str(fpath).endswith(fpath_stub):
            return code
        
def annotate(filepath, code, attrib, steps):
    lines = code.splitlines(keepends=True)
    base_lineno = int(attrib["line"])
    steps_to_lines = {}
    min_line = None
    max_line = None
    for s in steps:
        if s["attr"]["filepath"] == filepath:
            s = s.copy()
            lineno = int(s["attr"]["line"])-1
            relative_lineno = lineno-base_lineno
            s["relative_lineno"] = relative_lineno
            steps_to_lines[lineno] = s
            if min_line is None or lineno < min_line:
                min_line = lineno
            if max_line is None or lineno > max_line:
                max_line = lineno
    # Pairing of (line number, dict of variables which were assigned)
    steps_to_lines = list(sorted(steps_to_lines.items(), key=lambda p: p[0]))
    previous_variables = {}
    # TODO: Add line numbers to the code.
    # TODO: Offset step line numbers backwards by 1.
    # TODO: Don't print local variables until after they're first assigned.
    # 1. Parse the code with tree-sitter.
    # 2. Make a mapping from variable names to the location where they are first assigned.
    # 3. Move the item in the data structure (steps) to the location where it's first assigned.
    # TODO: Display structs and pointers in a way that's """"represented well to the model"""".
    for lineno, data in steps_to_lines:
        prefix = f" //__TREECUTTER_MARKER__: L{data['relative_lineno']+1}"
        variable_texts = []
        for vname, vdata in sorted(data["variables"].items(), key=lambda p: p[0]):
            if vdata["type_category"] == "pointer":
                continue
            if (vdata['type_category'] in ['string', 'integer'] or vdata["concrete_type"] in ["uint8_t", "uint32_t", "krb5_error_code"]) and "value" in vdata:
                value = vdata['value']
                value = vdata['value'].split()[0]
            else:
                value = vdata['concrete_type']
            # If variable hasn't changed since last step, don't print it
            if vname in previous_variables and value == previous_variables[vname]:
                continue
            previous_variables[vname] = value
            variable_text = f"{vname}={value}"
            variable_texts.append(variable_text)
        variable_summary = ", ".join(variable_texts)
        if len(variable_summary) > 0:
            variable_summary = " " + variable_summary
        del data["relative_lineno"]
        lines[lineno] = lines[lineno].rstrip() + prefix + variable_summary + "\n"
    return "".join(lines[min_line-2:max_line+1])

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("in_file", type=Path)
    p.add_argument("src_file", type=Path)
    p.add_argument("out_dir", type=Path)
    args = p.parse_args()

    in_file = args.in_file
    assert in_file.is_file()
    out_dir = args.out_dir
    out_dir.mkdir(exist_ok=True, parents=True)

    # Read src_*.xml and get a mapping of filepaths to source code
    fpath_to_text = {}
    tree = etree.parse(args.src_file)
    source_files = tree.getroot()
    for file_data in source_files:
        code = file_data.text
        # code = process(code, ["remove_comments", "remove_blank_lines"]) # Do this after appending traces as comments
        fpath_to_text[file_data.attrib["fpath"]] = code
    code = {}
    for _, file in etree.iterparse(in_file, events=["end"], tag="file"):
        code[file.attrib["fpath"]] = parse(file.text)

    # Go through log_*.xml and collect <call> tags
    tree = etree.parse(in_file) # Read the file to a tree structure
    trace = tree.getroot()
    calls = 0
    out_file = out_dir/f"{in_file.stem}.jsonl"
    with jsonlines.open(out_file, "w") as w:
        for call in trace.xpath("//call"): # Get all descendants of <trace> that are <call> tags
            if call.attrib["name"] == "LLVMFuzzerTestOneInput":
                continue
            # Serialize all <tracepoint> tags to steps
            steps = []
            for child in call:
                if child.tag == "call":
                    pass
                elif child.tag == "skip":
                    pass
                elif child.tag == "tracepoint":
                    steps.append(serialize_tracepoint(child))
                else:
                    raise NotImplementedError(child.tag)
            if len(steps) > 0:
                # Take the steps (tracepoints) and match them with the source code lines
                attrib = dict(call.attrib)
                code = get_file_code(fpath_to_text, call.attrib["filepath"])
                code_with_steps = annotate(call.attrib["filepath"], code, attrib, steps) # Add comments to the code
                code_processed = process(code_with_steps, ["remove_comments", "remove_blank_lines"]) # Remove all comments from the original code but keep our annotations
                w.write({
                    "attr": attrib,
                    "code_processed": code_processed,
                    "steps": steps,
                })
            calls += 1
    print("Call tags:", calls)
