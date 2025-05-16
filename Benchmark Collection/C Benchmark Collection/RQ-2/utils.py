import sys
import json
from lxml import etree
from pathlib import Path
import tree_sitter
from tree_sitter_languages import get_parser
import os
import argparse
import random
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

    return source_code, filtered_input, variables_dict, min_line, max_line