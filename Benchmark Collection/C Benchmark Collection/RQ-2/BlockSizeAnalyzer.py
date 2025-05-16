import json
import re
import tiktoken
from collections import defaultdict
from tree_sitter import Node
from tree_sitter_languages import get_parser
import sys
import os
from pathlib import Path
from lxml import etree

from utils import *

class BlockSizeAnalyzer:
    def __init__(self, code, variables_dict, input, project_name, min_line, max_line, language="c"):
        self.code = code
        self.input = input
        self.min_line = min_line,
        self.max_line = max_line,
        self.project_name = project_name
        self.variables_dict = variables_dict
        self.language = language
        self.parser = get_parser(language)
        self.tree = self.parser.parse(code.encode())
        self.lines = code.splitlines()
        self.clean_code = self._clean_code(code)
        self.clean_lines = self.clean_code.splitlines()
        
    def _clean_code(self, code):
        """Remove comments and blank lines from C code"""
        # Remove single-line comments
        code = re.sub(r'//.*?\n', '\n', code)
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Remove blank lines
        lines = [line for line in code.split('\n') if line.strip()]
        return '\n'.join(lines)
    
    def _get_function_body(self, node):
        """Extract function body from AST node"""
        body = node.child_by_field_name('body')
        if body:
            # Remove .decode('utf8') since self.code is already a string
            return self.code[body.start_byte:body.end_byte]
        return ""
    
    def _get_line_number(self, node):
        """Get line number from node"""
        return node.start_point[0] + 1  # 1-based indexing
    
    def _get_variable_values(self, line_number):
        """Get variable states at specific line number"""
        
        states = {}
        for var, entries in self.variables_dict.items():
            print(f"Variable:{var}")
            print(f"Entry:{entries}")
            for entry_line, entry_value in reversed(entries):
                print("True")
                print(entry_line)
                print(line_number)
                if entry_line < line_number:
                    states[var] = entry_value
                    break
        return states
    
    def _is_control_structure(self, line):
        """Check if line is a control structure"""
        stripped = line.strip()
        return (stripped.startswith(('if', 'else', 'for', 'while', 'switch')) or
                any(kw in stripped for kw in ['if', 'else', 'for', 'while', 'switch']))
    
    def _token_filter(self, code, max_tokens=2048):
        """Check if code is within token limit"""
        tokenizer = tiktoken.get_encoding("cl100k_base")
        return len(tokenizer.encode(code)) <= max_tokens

    def _get_nested_value(self, state, var_name):
        """Get value from potentially nested state dictionary, handling struct/pointer access"""
        if not state:
            return None
        
        # Clean the variable name by removing whitespace
        var_name = var_name.strip()
        
        def get_value(data, key):
            """Helper function to get value with None->Null conversion"""
            value = data.get(key) if isinstance(data, dict) else None
            return 'Null' if value is None else value
        
        # Handle pointer dereferences (buf->member)
        if '->' in var_name:
            parts = var_name.split('->')
            base_var = parts[0].strip()
            member = parts[1].strip()
            
            if base_var in state:
                if isinstance(state[base_var], dict):
                    return get_value(state[base_var], member)
                elif isinstance(state[base_var], str):
                    try:
                        nested = json.loads(state[base_var])
                        return get_value(nested, member)
                    except json.JSONDecodeError:
                        pass
            return None
        
        # Handle struct member access (var.member)
        elif '.' in var_name:
            parts = var_name.split('.')
            current = state
            for part in parts:
                if isinstance(current, dict):
                    current = get_value(current, part)
                    if current == 'Null':
                        break
                else:
                    return None
            return current
        
        # Handle direct variable access
        elif var_name in state:
            return get_value(state, var_name)
        
        elif '[' in var_name and ']' in var_name:
            base_var = var_name.split('[')[0]
            if base_var in state:
                return get_value(state, base_var)
        
        return None

    def _is_assignment(self, line):
        """Check if line is an assignment and return components"""
        line = line.strip()
        if '=' in line:
            parts = line.split('=', 1)
            lhs = parts[0].strip()
            rhs = parts[1].strip()
            return True, lhs, rhs
        return False, None, None
    
    def analyze_blocks(self, n_values):
        """Analyze code at different block sizes (line numbers)"""
        results = []
        
        # Skip if code exceeds token limit
        if not self._token_filter(self.clean_code):
            return results
        
        # Process each function in the code
        functions = []
        def collect_functions(node):
            if node.type == "function_definition":
                functions.append(node)
            for child in node.children:
                collect_functions(child)
        collect_functions(self.tree.root_node)
        
        for func_node in functions:
            func_body = self._get_function_body(func_node)
            if not func_body:
                continue
                
            clean_func_lines = self._clean_code(func_body).splitlines()
            
            for n in n_values:
                if n >= len(clean_func_lines):
                    continue
                    
                target_line = clean_func_lines[n]
                line_number = self._get_line_number(func_node) + n
                
                # Skip control structures
                if self._is_control_structure(target_line):
                    continue
                
                # Get state at this line
                state = self._get_variable_values(line_number)
                print(state)
                
                if "return" in target_line:
                    variable = target_line.split(" ")[1]
                    state = self._get_nested_value(state, variable)
                    
                
                # Check if this is an assignment
                is_assignment, lhs, rhs = self._is_assignment(target_line)
                if is_assignment:
                    rhs = rhs.rstrip(';').strip()
                    previous_state = self._get_variable_values(line_number - 1) if line_number > 1 else {}
                    # Get the value that will be assigned (either literal or variable value)
                    if (rhs.isdigit() or 
                        (rhs.startswith('"') and rhs.endswith('"')) or 
                        (rhs.startswith("'") and rhs.endswith("'")) or
                        rhs == 'NULL' or 
                        rhs.lower() in ('true', 'false')):
                        
                        assigned_value = rhs
                    else:
                        #For variables, look up their value in the state
                        # print(f"State: {state}")
                        # print(f"lhs:{lhs}")
                        assigned_value = self._get_nested_value(state, lhs)
                        #print(assigned_value)
                    

                    
                    output_data = {
                        'Programming Language': 'C',
                        'Source Code': self.clean_code,
                        'Selected Statement': target_line,
                        'Function Input': self.input,
                        'Value After Statement Execution': assigned_value,
                        'Variable States During Runtime': "N/A",
                        'Block_Size': n,
                        'Project Information': {
                            'Project Name': self.project_name,
                        }
                    }
                    results.append(output_data)
                else:
                    # Handle non-assignment statements (existing logic)
                    if state:
                        output_data = {
                            'Programming Language': 'C',
                            'Source Code': self.clean_code,
                            'Selected Statement': target_line,
                            'Function Input': self.input,
                            'Value After Statement Execution': state,
                            'Variable States During Runtime': "N/A",
                            'Block_Size': n,
                            'Project Information': {
                                'Project Name': self.project_name,
                            }
                        }
                        results.append(output_data)
        
        return results
    
    def _get_function_name(self, func_node):
        """Extract function name from node"""
        declarator = func_node.child_by_field_name('declarator')
        if declarator:
            identifier = declarator.child_by_field_name('identifier')
            if identifier:
                return self.code[identifier.start_byte:identifier.end_byte].decode('utf8')
        return "unknown"

def process_xml_for_block_analysis(in_file, src_file, output_file, n_values):
    """Process XML traces for block size analysis"""
    # Parse source files
    with open(src_file) as f:
        src_tree = etree.parse(f)
    src_files = {file.attrib["fpath"]: file.text for file in src_tree.xpath("//file")}
    
    # Parse execution traces
    with open(in_file) as f:
        trace_tree = etree.parse(f)
    
    stats = defaultdict(int)
    
    with open(output_file, 'a') as outfile:
        for call in trace_tree.xpath("//call"):
            if call.attrib["name"] == "LLVMFuzzerTestOneInput":
                continue
                

            filepath = call.attrib["filepath"]
            code = src_files.get(filepath)
            if not code:
                stats['no_code_skipped'] += 1
                continue
                
            steps = []
            for child in call:
                if child.tag == "tracepoint":
                    steps.append(serialize_tracepoint(child))
            
            try:
                result = annotate(call.attrib["filepath"], code, call.attrib, steps)
                
                #print(result)
                if result is None:
                    stats['annotate_failed'] += 1
                    continue
                    
                annotated_code, input, variables_dict, min_line, max_line = result
                

               
                project_name = in_file.split('traces/')[1].split('_own')[0]
                
                # Analyze block sizes
                analyzer = BlockSizeAnalyzer(
                    annotated_code, variables_dict, input, project_name, min_line, max_line
                )
                results = analyzer.analyze_blocks(n_values)
                
                
                # Write results
                for result in results:
                    outfile.write(json.dumps(result) + '\n')
                    stats[f'n_{result["Block_Size"]}'] += 1
                    stats['total'] += 1
                    
            except Exception as e:
                # print(f"Error processing call {call.attrib.get('name')}: {str(e)}")
                # stats['processing_errors'] += 1
                continue
    
    # Print statistics
    # print("\nBlock Size Analysis Statistics:")
    # print(f"Total calls processed: {len(trace_tree.xpath('//call'))}")
    # print(f"Skipped (no code): {stats.get('no_code_skipped', 0)}")
    # print(f"Skipped (annotation failed): {stats.get('annotate_failed', 0)}")
    # print(f"Processing errors: {stats.get('processing_errors', 0)}")
    # print("\nSamples per n value:")
    # for n in n_values:
    #     print(f"n={n}: {stats.get(f'n_{n}', 0)}")
    # print(f"\nTotal samples: {stats.get('total', 0)}")

# n_values = [1, 2, 3, 4, 5, 10, 15, 20, 25]
# process_xml_for_block_analysis(
#     '/home/XXX/trace-modeling-oss-fuzz-c/trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/log_698.xml',
#     '/home/XXX/trace-modeling-oss-fuzz-c/trace_test/traces/krb5_own/trace_Fuzz_ndr_exe/src_698.xml',
#     'c_block_analysis.jsonl',
#     n_values
# )

def data_collection(log_file, output_jsonl="c_block_analysis_new.jsonl", n_values=[1, 2, 3, 4, 5]):
    src_file_path = Path(str(log_file).replace("log_", "src_"))
    
    if not src_file_path.exists():
        print(f"Source file not found: {src_file_path}")
        return None

    try:
        process_xml_for_block_analysis(
            str(log_file),
            str(src_file_path),
            output_jsonl,
            n_values
        )
        return True
    except Exception as e:
        print(f"Error processing {log_file}: {str(e)}")
        return False
    
import argparse
from pathlib import Path

# Add this at the end of your existing code
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process code execution traces')
    parser.add_argument('--log_file', type=str, help='Path to the log file (e.g., log_698.xml)')
    parser.add_argument('--output', type=str, default="c_block_analysis_new.jsonl",
                       help='Output JSONL filename')
    parser.add_argument('--n_values', type=str, default="1,2,3,4,5",
                       help='Comma-separated list of n values (e.g., "1,2,3,4,5")')

    args = parser.parse_args()
    
    # Convert n_values string to list of integers
    try:
        n_values = [int(n) for n in args.n_values.split(',')]
    except ValueError:
        raise ValueError("Invalid n_values format. Use comma-separated integers (e.g., '1,2,3,4,5')")

    # Run the data collection process
    result = data_collection(
        log_file=Path(args.log_file),
        output_jsonl=args.output,
        n_values=n_values
    )
    
    if result:
        print(f"Successfully processed {args.log_file}")
    else:
        print(f"Failed to process {args.log_file}")