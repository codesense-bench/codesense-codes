import sys
import json
from lxml import etree
from pathlib import Path
import tree_sitter
from tree_sitter_languages import get_parser
from CodeSampler import *
import os
import argparse
import random

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
    return {
        "type": node.tag,
        "attr": attributes,
        "variables": variables,
    }

def parse(text):
    parser = get_parser("c")
    tree = parser.parse(text.encode())
    functions = {}
    queue = [tree.root_node]
    while queue:
        node = queue.pop(0)
        if node.type == "function_definition":
            function_declarator = node.child_by_field_name("declarator")
            if function_declarator:
                function_name_node = function_declarator.child_by_field_name("declarator")
                if function_name_node and function_name_node.type == "identifier":
                    function_name = function_name_node.text.decode()
                    function_code = node.text.decode()
                    functions[function_name] = function_code
        queue.extend(node.children)
    return functions

def get_file_code(files, fpath_stub):
    for fpath, code in files.items():
        if str(fpath).endswith(fpath_stub):
            return code

def get_value(dictionary):
    if 'value' in dictionary and isinstance(dictionary['value'], dict):
        return get_value(dictionary['value'])
    elif 'value' in dictionary:
        return dictionary['value']
    else:
        return None
    
def get_function_parameters(code):
    """Extract parameter names from the first function definition in the code"""
    parser = get_parser("c")
    tree = parser.parse(code.encode())
    root = tree.root_node
    
    parameters = []
    
    def extract_parameter_name(node):
        """Recursively extract parameter name from declaration nodes"""
        if node.type == "identifier":
            return node.text.decode()
        elif node.type == "pointer_declarator":
            # Handle nested pointer declarators (like **out)
            decl = node.child_by_field_name("declarator")
            if decl:
                return extract_parameter_name(decl)
        elif node.type == "parameter_declaration":
            # Handle direct declarations (like 'data')
            decl = node.child_by_field_name("declarator")
            if decl:
                return extract_parameter_name(decl)
        return None
    
    def find_first_function(node):
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if declarator:
                parameters_node = declarator.child_by_field_name("parameters")
                if parameters_node:
                    for child in parameters_node.children:
                        if child.type == "parameter_declaration":
                            param_name = extract_parameter_name(child)
                            if param_name:
                                parameters.append(param_name)
                    return True
        for child in node.children:
            if find_first_function(child):
                return True
        return False
    
    find_first_function(root)
    return parameters
    

def annotate(filepath, code, attrib, steps, project_name):
    lines = code.splitlines(keepends=True)
    base_lineno = int(attrib["line"])
    steps_to_lines = {}
    min_line = None
    max_line = None
    
    variables_dict = {}
    
    
    for s in steps:        
        if s["attr"]["filepath"] == filepath:
            if s["attr"]["type"] == "entry":
                input = s["variables"]
            s = s.copy()
            lineno = int(s["attr"]["line"])-2
            steps_to_lines[lineno] = s
            if min_line is None or lineno < min_line:
                min_line = lineno
            if max_line is None or lineno > max_line:
                max_line = lineno
                
    steps_to_lines = list(sorted(steps_to_lines.items(), key=lambda p: p[0])) 
    
    previous_variables = {}
    for lineno, data in steps_to_lines:
        variable_texts = []
        for vname, vdata in sorted(data["variables"].items(), key=lambda p: p[0]):
            value = ""
            if vdata["type_category"] == "pointer" and "value" in vdata:
                if "value" in vdata['value'].keys() and vdata['value']['type_category'] != 'struct':
                    value = get_value(vdata['value'])
                elif vdata['value']['type_category'] == 'struct' and vdata['value']['concrete_type'] != 'error':
                    struct_dict = {}
                    for key in vdata['value']['value']:
                        dict_data = get_value(vdata['value']['value'][key])
                        struct_dict[key] = dict_data
                    value = struct_dict
            elif (vdata['type_category'] in ['string', 'integer'] or vdata["concrete_type"] in ["uint8_t", "uint16_t", "uint32_t", "uint64_t","int8_t", "int16_t", "int32_t", "int64_t", "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t", "pid_t", "uid_t", "gid_t", "off_t", "time_t", "mode_t", "byte", "BYTE", "word", "WORD", "dword", "DWORD", "qword", "QWORD", "BOOL","integer", "unsigned", "signed", "long", "short" ]) and "value" in vdata:
                value = vdata['value']
            elif (vdata['type_category'] in ['STRUCT', 'struct']) and 'value' in vdata:
                struct_dict = {}
                for key in vdata['value']:
                    dict_data = get_value(vdata['value'][key])
                    struct_dict[key] = dict_data
                value = struct_dict
            else:
                value = vdata['concrete_type']
            if vname not in variables_dict:
                variables_dict[vname] = {
                    'values': [],
                    'type': vdata.get('concrete_type', None)
                }
            variables_dict[vname]['values'].append((lineno, value))
    
    parameters = get_function_parameters(code)

    filtered_input = {
        k: {'value': v.get('value', None)} 
        for k, v in input.items() 
        if k in parameters
    }

    all_results = []
    last_code = "".join(lines[min_line-2:max_line+1])
    for lineno, data in steps_to_lines:
        line = lines[lineno].strip()
        if line:
            line_results = sample_statement(
                line, 
                variables_dict, 
                lineno,
                filtered_input,  
                project_name,
                last_code
            )
            if line_results:
                all_results.extend(line_results)

    executed_branches = set()
    for lineno, data in steps_to_lines:
        line = lines[lineno].strip()
        if line and line.startswith(('if (')):
            executed_branches.add(lineno)

    all_branches = []
    for i, line in enumerate(lines):
        line = line.strip()
        if line.startswith(('if (')):
            all_branches.append(i)

    not_executed = [lineno for lineno in all_branches if lineno not in executed_branches]
    sampled_not_executed = random.sample(not_executed, min(2, len(not_executed)))

    for lineno in sampled_not_executed:
        line = lines[lineno].strip()
        if line:
            line_results = sample_statement(
                line, 
                variables_dict, 
                lineno,
                filtered_input,  
                project_name,
                last_code,
                executed=False
            )
            if line_results:
                all_results.extend(line_results)
       
    return all_results


def process_xml_to_code(in_file, src_file, seen_signatures_global = None, output_dir="output"):
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"Error creating output directory: {e}", file=sys.stderr)
        return None

    statement_types = [
        "Constant Assignment",
        "Assignment",
        "Arithmetic Assignment",
        "Branch",
        "Function Call",
    ]
    
    try:
        jsonl_files = {
            stype: open(os.path.join(output_dir, f"{stype}.jsonl"), "a") 
            for stype in statement_types
        }
    except Exception as e:
        print(f"Error opening JSONL files: {e}", file=sys.stderr)
        return None

    seen_signatures = seen_signatures_global if seen_signatures_global is not None else set()
    fpath_to_text = {}
    
    try:
        project_name = in_file.split('traces/')[1].split('_own')[0]
    except IndexError as e:
        print(f"Invalid file path format: {in_file}", file=sys.stderr)
        return None

    # Parse source XML
    try:
        if not os.path.exists(src_file):
            raise FileNotFoundError(f"Source file not found: {src_file}")
        if not os.access(src_file, os.R_OK):
            raise PermissionError(f"No read permission for: {src_file}")

        parser = etree.XMLParser(resolve_entities=False, recover=True)
        tree = etree.parse(src_file, parser=parser)
        source_files = tree.getroot()
        
        for file_data in source_files:
            try:
                if file_data.text:
                    fpath_to_text[file_data.attrib["fpath"]] = file_data.text
            except KeyError:
                print(f"Missing 'fpath' attribute in source file", file=sys.stderr)
                continue
            except Exception as e:
                print(f"Error processing source file entry: {e}", file=sys.stderr)
                continue
                
    except Exception as e:
        print(f"Error processing source file: {e}", file=sys.stderr)
        return None

    # Parse trace file
    try:
        try:
            trace_tree = etree.parse(in_file, parser=etree.XMLParser(resolve_entities=False))
        except etree.XMLSyntaxError:
            print(f"Falling back to HTML parser for {in_file}", file=sys.stderr)
            trace_tree = etree.parse(in_file, parser=etree.HTMLParser())
            
        trace = trace_tree.getroot()
        total_samples = {stype: 0 for stype in statement_types}
        
        for call in trace.xpath("//call"):
            try:
                if call.attrib.get("name") == "LLVMFuzzerTestOneInput":
                    continue
                    
                steps = []
                for child in call:
                    try:
                        if child.tag == "tracepoint":
                            steps.append(serialize_tracepoint(child))
                        elif child.tag not in ("call", "skip"):
                            print(f"Unexpected tag {child.tag}", file=sys.stderr)
                    except Exception as e:
                        print(f"Error processing tracepoint: {e}", file=sys.stderr)
                        continue
                        
                if steps:
                    try:
                        attrib = dict(call.attrib)
                        file_code = get_file_code(fpath_to_text, call.attrib["filepath"])
                        
                        if file_code in seen_signatures:
                            continue
                        seen_signatures.add(file_code)
                        
                        all_results = annotate(
                            call.attrib["filepath"], 
                            file_code, 
                            attrib, 
                            steps, 
                            project_name
                        )
                        
                        if not all_results:
                            continue
                        
                        filtered_results = []
                        type_counts = {
                            "Branch": {"Yes": 0, "No": 0},
                            "Constant Assignment": 0,
                            "Assignment": 0, 
                            "Arithmetic Assignment": 0,
                            "Function Call": 0
                        }
                        import random
                        random.shuffle(all_results)
                        
                        for result in all_results:
                            stype = result["Statement Type"]
                            
                            if stype == "Branch":
                                branch_type = result.get("Value After Statement Execution", "Yes")
                                if type_counts["Branch"][branch_type] < 2:
                                    filtered_results.append(result)
                                    type_counts["Branch"][branch_type] += 1
                            else:
                                if type_counts[stype] < 1:
                                    filtered_results.append(result)
                                    type_counts[stype] += 1
                            
                            if (all(count >= 1 for stype, count in type_counts.items() if stype != "Branch") and
                                all(count >= 2 for count in type_counts["Branch"].values())):
                                break
                        
                            
                        for result in filtered_results:
                            try:
                                stype = result["Statement Type"]
                                if stype in jsonl_files:
                                    jsonl_files[stype].write(json.dumps(result) + "\n")
                                    total_samples[stype] += 1
                            except KeyError:
                                print("Missing 'Statement Type' in result", file=sys.stderr)
                                continue
                            except Exception as e:
                                print(f"Error writing result: {e}", file=sys.stderr)
                                continue
                                
                    except KeyError as e:
                        print(f"Missing attribute {e} in call", file=sys.stderr)
                        continue
                    except Exception as e:
                        print(f"Error processing call: {e}", file=sys.stderr)
                        continue
                        
            except Exception as e:
                print(f"Error processing call element: {e}", file=sys.stderr)
                continue
                
    except Exception as e:
        print(f"Fatal error processing trace file {in_file}: {e}", file=sys.stderr)
        return None
    finally:
        try:
            for f in jsonl_files.values():
                f.close()
        except Exception as e:
            print(f"Error closing files: {e}", file=sys.stderr)

    print("\nSample collection summary:")
    for stype, count in total_samples.items():
        print(f"{stype}: {count} samples")
    
    return total_samples




# Modify the main function to accept output directory
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in_file", type=str, help="Path to the input file")
    parser.add_argument("--src_file", type=str, help="Path to the source file")
    parser.add_argument("--output_dir", type=str, default="output", 
                       help="Directory to save JSONL files")
    args = parser.parse_args()
    
    total_samples = process_xml_to_code(args.in_file, args.src_file, None, args.output_dir, )
    
    print(f"\nAll samples saved to {args.output_dir} directory")

if __name__ == "__main__":
    main()

# Example usage in another script or notebook:
# code_processed_list = process_xml_to_code(Path("/home/XXX/trace-modeling-oss-fuzz-c/trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/log_698.xml"), Path("/home/XXX/trace-modeling-oss-fuzz-c/trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/src_698.xml"))