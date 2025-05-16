import sys
sys.path.append("/home/XXX/trace-modeling-oss-fuzz-c/scripts/postprocessing2/tree-cutter")
import json
from lxml import etree
from pathlib import Path
from tree_cutter import process
import tree_sitter
from tree_sitter_languages import get_parser
import os
import argparse
import random
import re
from function_name import *

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

def remove_comments(c_code):
    single_line_comment = r"//.*?$"
    multi_line_comment = r"/\*.*?\*/"
    
    no_multi_line = re.sub(multi_line_comment, "", c_code, flags=re.DOTALL)
    

    no_comments = re.sub(single_line_comment, "", no_multi_line, flags=re.MULTILINE)
    
    return no_comments.strip()

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
    
import tree_sitter
from tree_sitter_languages import get_parser

def extract_variables_from_line(line):
    parser = get_parser("c")
    tree = parser.parse(line.encode())
    root = tree.root_node
    
    variables = set()

    def is_variable_node(node):
        # Check if this identifier is being used as a variable
        parent = node.parent
        if not parent:
            return False
            
        # Cases where identifier is a variable:
        # 1. In a binary expression (e.g., bytes in "bytes == NULL")
        # 2. As a function argument (e.g., bytes in "func(bytes)")
        # 3. In an assignment (either side)
        # 4. In a declaration (but declarations usually need full context)
        return parent.type in [
            'binary_expression',
            'argument_list',
            'assignment_expression',
            'declaration'
        ]

    def traverse(node):
        if node.type == "identifier" and is_variable_node(node):
            variables.add(node.text.decode())
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    return variables
    

def annotate(filepath, code, attrib, steps):
    lines = code.splitlines(keepends=True)
    source_code = extract_complete_function(code, steps[0]['attr']['func_name'])
    
    if not source_code:
        return None, None, None
    
    base_lineno = int(attrib["line"])
    steps_to_lines = {}
    min_line = base_lineno
    max_line = min_line + len(source_code.splitlines(keepends=True))
    variables_dict = {}
    pointer_address_mapping = {}
    aliasing_results = {} 

    input = steps[0]['variables']
    
    
    for s in steps:
        if s["attr"]["filepath"] == filepath:
            s = s.copy()
            lineno = int(s["attr"]["line"]) - 2
            

            steps_to_lines[lineno] = s
            # if min_line is None or lineno < min_line:
            #     min_line = lineno
            # if max_line is None or lineno > max_line:
            #     max_line = lineno

    steps_to_lines = sorted(steps_to_lines.items(), key=lambda p: p[0])

    # print(f"Min:{min_line}")
    # print(f"Max:{max_line}")
    # First pass: Build pointer address mapping
    for lineno, data in steps_to_lines:
        variable_list = extract_variables_from_line(lines[lineno])
        for vname, vdata in sorted(data["variables"].items(), key=lambda p: p[0]):
            if (vdata["type_category"] in ("pointer", "POINTER") and 
                "value" in vdata and "address" in vdata):
                if vname in variable_list:
                    pointer_address_mapping[vname] = {
                        "address":vdata['address'],
                        "line": lines[lineno],
                    }
            elif (vdata["type_category"] in ("string", "STRING") and 
                "value" in vdata):
                if vname in variable_list:
                    pointer_address_mapping[vname] = {
                        "address":vdata['value'].split(' '),
                        "line": lines[lineno],
                    }

    # Second pass: Detect aliasing
    yes_aliases = []
    no_aliases = []
    for lineno, data in steps_to_lines:
        variable_list = extract_variables_from_line(lines[lineno])
        
        for var in variable_list:
            if var in pointer_address_mapping:
                address_line = pointer_address_mapping[var]
                current_address = pointer_address_mapping[var]['address']
                
                for variable_name, address in pointer_address_mapping.items():
                    if address['address'] == current_address and variable_name != var and (lineno > min_line and lineno < max_line):
                        next_line_no = lineno + 1
                        while next_line_no < max_line:
                            next_line = lines[next_line_no].strip()
                            if next_line:  
                                yes_aliases.append({
                                    "Selected Statement": lines[next_line_no],
                                    "Selected Pointer": var,  
                                    "Compared Statement": address['line'],
                                    "Compared Pointer": variable_name,
                                    "Aliasing": "Yes",
                                })
                                break  
                            next_line_no += 1
                        else:
                            yes_aliases.append({
                                "Selected Statement": address_line['line'],
                                "Selected Pointer": var,
                                "Compared Statement": address['line'],
                                "Compared Pointer": variable_name,
                                "Aliasing": "Yes",
                            })
                            
                    elif address_line['line'] != address['line'] and (lineno > min_line and lineno < max_line):
                        no_aliases.append({
                            "Selected Statement": address_line['line'],
                            "Selected Pointer": var, 
                            "Compared Statement": address['line'],
                            "Compared Pointer": variable_name,
                            "Aliasing": "No",
                        })
        if len(yes_aliases) == 0 and len(no_aliases) == 0:
            alias = None
        elif len(yes_aliases) == 0 and len(no_aliases) > 0:
            alias = random.choice(no_aliases)
        else:
            alias = random.choice(yes_aliases)
    return source_code, input, alias

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
            decl = node.child_by_field_name("declarator")
            if decl:
                return extract_parameter_name(decl)
        elif node.type == "parameter_declaration":
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


import tiktoken

def count_tokens_llm(text, model="gpt-4"):
    encoding = tiktoken.encoding_for_model(model)
    return len(encoding.encode(str(text)))

def process_xml_to_code(in_file, src_file):
    fpath_to_text = {}
    result = {
        "Programming Language": "C",
        "Source Code": "",
        "Selected Statement": "",
        "Selected Pointer": "",
        "Compared Statement": "",
        "Compared Pointer": "",
        "Aliasing":"",
        "Function Input": {},
        "Program Information": {}
    }
    
    # 1. Get project name
    try:
        project_name = in_file.split('traces/')[1].split('_own')[0]
        result["Program Information"]["Project Name"] = project_name
    except IndexError as e:
        print(f"Invalid file path format: {in_file}", file=sys.stderr)
        return None

    # 2. Parse source XML
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
        print(f"Error processing source file: {e}", file=sys.stderr)
        return None

    # 3. Parse trace file
    try:
        try:
            trace_tree = etree.parse(in_file, parser=etree.XMLParser(resolve_entities=False))
        except etree.XMLSyntaxError:
            print(f"Falling back to HTML parser for {in_file}", file=sys.stderr)
            trace_tree = etree.parse(in_file, parser=etree.HTMLParser())
            
        trace = trace_tree.getroot()
        
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
                        
                        
                        #print(attrib)
                        
                        code, input, aliasing_info = annotate(
                            call.attrib["filepath"], file_code, attrib, steps
                        )
                        if (code is None or aliasing_info is None) or len(code) == 0:
                            continue
                        
                        parameters = get_function_parameters(code)

                        filtered_input = {
                            k: v for k, v in input.items() 
                            if k in parameters
                        }
                        
                        if (len(aliasing_info.get("Selected Statement", "")) == 0 and
                            len(aliasing_info.get("Selected Pointer", "")) == 0 and
                            len(aliasing_info.get("Compared Statement", "")) == 0 and
                            len(aliasing_info.get("Compared Pointer", "")) == 0):
                            continue
                        
                        
                        
                        clean_code = remove_comments(code)
                        code_tokens = count_tokens_llm(clean_code)
                        input_tokens = count_tokens_llm(json.dumps(filtered_input))
                        total_tokens = code_tokens + input_tokens
                        
                        
                        if total_tokens >= 2500:
                            print(f"Skipping - Token count {total_tokens} >= 2500")
                            continue
                        result["Source Code"] = clean_code
                        result["Function Input"] = filtered_input
                    

                        
                        if isinstance(aliasing_info, dict):
                            result.update({
                                "Selected Statement": aliasing_info.get("Selected Statement", ""),
                                "Selected Pointer": aliasing_info.get("Selected Pointer", ""),
                                "Compared Statement": aliasing_info.get("Compared Statement", ""),
                                "Compared Pointer": aliasing_info.get("Compared Pointer", ""),
                                "Aliasing": aliasing_info.get("Aliasing", ""),
                            })
                            
                    except KeyError as e:
                        print(f"Missing attribute {e} in call", file=sys.stderr)
                        continue
                        
            except Exception as e:
                print(f"Error processing call: {e}", file=sys.stderr)
                continue
                
        return result
        
    except Exception as e:
        print(f"Fatal error processing trace file {in_file}: {e}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in_file", type=str, help="Path to the input file")
    parser.add_argument("--src_file", type=str, help="Path to the source file")

    args = parser.parse_args()
    
    result = process_xml_to_code(args.in_file, args.src_file)

    # if isinstance(result, dict):  # Single result case
    #     print("Source Code:")
    #     print(result.get('Source Code', ''))
    #     print("\nSelected Statement:")
    #     print(result.get('Selected Statement', ''))
    #     print("\nSelected Pointer:")
    #     print(result.get('Selected Pointer', ''))
    #     print("\nCompared Pointer:")
    #     print(result.get('Compared Pointer', ''))
    # elif isinstance(result, list):  # Multiple results case
    #     for sample in result:
    #         print("Source Code:")
    #         print(sample.get('Source Code', ''))
    #         print("\nSelected Pointer:")
    #         print(result.get('Selected Pointer', ''))
    #         print("\nCompared Pointer:")
    #         print(result.get('Compared Pointer', ''))
    # else:
    #     print("Unexpected result type:", type(result))
    
    # if result:
    #     print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

# Example usage in another script or notebook:
# code_processed_list = process_xml_to_code(Path("/home/XXX/trace-modeling-oss-fuzz-c/trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/log_698.xml"), Path("/home/XXX/trace-modeling-oss-fuzz-c/trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/src_698.xml"))