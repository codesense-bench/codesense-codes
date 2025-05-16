from tree_sitter_languages import get_parser
import os
import json

parser = get_parser("c")

def get_function_signatures(source_code):
    """
    Parse the source code of a C file and extract function signatures.
    """
    tree = parser.parse(bytes(source_code, "utf8"))
    root_node = tree.root_node

    function_signatures = []

    for node in root_node.children:
        if node.type == 'function_definition':
            try:
                return_type = source_code[node.child_by_field_name('type').start_byte:node.child_by_field_name('type').end_byte]
                function_declarator = node.child_by_field_name('declarator')
                function_name = function_declarator.child_by_field_name('declarator').text.decode('utf8')
                if function_declarator is not None:
                    function_signature = return_type + " " + source_code[function_declarator.start_byte:function_declarator.end_byte]
                    function_signatures.append({
                        "start_point": node.start_point,
                        "end_point": node.end_point,
                        "function": function_name,
                        "signature": " ".join(function_signature.split()),
                    })
                # function_name = node.child_by_field_name('declarator').child_by_field_name('declarator').text.decode('utf8')
                # function_signature = source_code[node.start_byte:node.end_byte]
                # function_signatures.append((function_name, function_signature))
            except Exception as e:
                print(f"{e}: Failed to handle function: {node.text.decode()}")

    return function_signatures

def walk_directory_and_parse_functions(directory_path):
    """
    Walk through the given directory, parse each C file and extract function signatures.
    """
    all_function_signatures = {}

    for root, dirs, files in os.walk(directory_path):
        myroot = os.path.relpath(root, directory_path)
        # myroot = root
        for file in files:
            if file.endswith(".c"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding="utf-8", errors="ignore") as f:
                    source_code = f.read()
                    signatures = get_function_signatures(source_code)
                    all_function_signatures[os.path.join(myroot, file)] = signatures

    return all_function_signatures

def write_to_file(data, fpath):
    with open(fpath, "w") as f:
        for fname, signatures in data.items():
            for signature_data in signatures:
                f.write(json.dumps({"file": fname, **signature_data}) + "\n")    

if __name__ == "__main__":
    functions_by_file = walk_directory_and_parse_functions("/home/XXX/Code/trace-modeling/oss-fuzz-c/code/libucl/src/libucl")
    write_to_file(functions_by_file, "/home/XXX/Code/trace-modeling/oss-fuzz-c/code/libucl/functions.jsonl")
    # functions_by_file = walk_directory_and_parse_functions("/home/XXX/Code/trace-modeling/oss-fuzz-c/code/apache-httpd/src/httpd")
    # write_to_file(functions_by_file, "/home/XXX/Code/trace-modeling/oss-fuzz-c/code/apache-httpd/functions.jsonl")
