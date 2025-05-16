import tree_sitter
from tree_sitter_languages import get_parser
import random
import re
import tiktoken
import json

def remove_comments(code):
    code = re.sub(r'//.*?\n', '\n', code)  # Single-line
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)  # Multi-line
    return code

def count_tokens(text, encoding_name="cl100k_base"):
    """Count tokens using tiktoken (accurate for GPT-style tokenization)."""
    encoding = tiktoken.get_encoding(encoding_name)
    return len(encoding.encode(text))

def is_code_within_token_limit(code, max_tokens=1024):
    """Check if code (after comment removal) has <= max_tokens."""
    #processed_code = remove_comments(code)
    return count_tokens(code) <= max_tokens

def parse_code(code, language="c"):
    """Parse the code using Tree-sitter and return the root node."""
    parser = get_parser(language)
    tree = parser.parse(code.encode())
    return tree.root_node

def sample_statement(line, variables_dict, current_lineno, function_input, project_info, code, block_size):
    parser = get_parser("c")
    tree = parser.parse(line.encode())
    root = tree.root_node
    
    code = remove_comments(code)
    total_code = code + json.dumps(function_input)
    
    if not is_code_within_token_limit(total_code, max_tokens=2000):
        return None
    
    results = []
    stack = [root]
    
    def get_post_recent_value(var_name, lineno):
        """Helper to get the most recent value before or at the given line"""
        if var_name in variables_dict and '->' not in var_name:
            for entry in variables_dict[var_name]['values']:
                if entry[0] > lineno:
                    return entry[1]
    
        if '->' in var_name:
            base_var, member = var_name.split('->', 1)
            base_var = base_var.strip()
            member = member.strip()
            
            base_value = get_post_recent_value(base_var, lineno)
            
            if isinstance(base_value, dict) and member in base_value:
                return base_value[member]
            elif isinstance(base_value, dict):
                return base_value.get(member, None)
        elif '.' in var_name:
            base_var, member = var_name.split('.', 1)
            base_var = base_var.strip()
            member = member.strip()
            
            base_value = get_post_recent_value(base_var, lineno)
            
            if isinstance(base_value, dict) and member in base_value:
                return base_value[member]
            elif isinstance(base_value, dict):
                return base_value.get(member, None)
        
        return None

    def get_most_recent_value(var_name, lineno):
        """Helper to get the most recent value before or at the given line"""
        if var_name in variables_dict and '->' not in var_name:
            # First try to find exact line match
            for entry in reversed(variables_dict[var_name]['values']):
                if entry[0] == lineno:
                    return entry[1]
            # If not found, get most recent before line
            for entry in reversed(variables_dict[var_name]['values']):
                if entry[0] <= lineno:
                    return entry[1]
    
        if '->' in var_name:
            base_var, member = var_name.split('->', 1)
            base_var = base_var.strip()
            member = member.strip()
            
            base_value = get_most_recent_value(base_var, lineno)
            
            if isinstance(base_value, dict) and member in base_value:
                return base_value[member]
            elif isinstance(base_value, dict):
                return base_value.get(member, None)
        elif '.' in var_name:
            base_var, member = var_name.split('.', 1)
            base_var = base_var.strip()
            member = member.strip()
            
            base_value = get_most_recent_value(base_var, lineno)
            
            if isinstance(base_value, dict) and member in base_value:
                return base_value[member]
            elif isinstance(base_value, dict):
                return base_value.get(member, None)
        
        return None


    def evaluate_expression(node):
        """Helper to evaluate binary expressions"""
        if node.type == "identifier":
            var_name = line[node.start_byte:node.end_byte]
            return get_most_recent_value(var_name, current_lineno)
        elif node.type in ["number_literal", "string_literal"]:
            return line[node.start_byte:node.end_byte]
        elif node.type == "binary_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            
            operator = next(
                child for child in node.children 
                if child.type in {
                    "+", "-", "*", "/", 
                    "+=", "-=", "*=", "/=",
                    "==", "!=", "<", ">", "<=", ">="
                }
            )
            
            if operator.type.endswith("=") and operator.type != "==":
                return evaluate_expression(left)
                
            left_val = evaluate_expression(left)
            right_val = evaluate_expression(right)
            
            if left_val is None or right_val is None:
                return None
                
            try:
                if operator.type == "+":
                    return str(int(left_val) + int(right_val))
                elif operator.type == "-":
                    return str(int(left_val) - int(right_val))
                elif operator.type == "*":
                    return str(int(left_val) * int(right_val))
                elif operator.type == "/":
                    return str(int(left_val) // int(right_val))
                elif operator.type in ["==", "!=", "<", ">", "<=", ">="]:
                    return evaluate_expression(left)
            except (ValueError, TypeError):
                return None
        elif node.type == "call_expression":
            return None
        return None

    def collect_condition_variables(node):
        """Collect variables from a condition expression"""
        variables = {}
        
        def collect(node):
            # Skip parentheses and other non-relevant nodes
            if node.type in ["(", ")", "parenthesized_expression", "{", "}"]:
                for child in node.children:
                    collect(child)
                return
            
            # Handle identifiers (like 'nservices', 'buf')
            if node.type == "identifier":
                var_name = line[node.start_byte:node.end_byte]
                var_value = get_most_recent_value(var_name, current_lineno)
                variables[var_name] = var_value if var_value else "NULL"
                return
            
            # Handle struct member access (-> and .)
            if node.type == "field_expression":
                base_node = node.child_by_field_name("argument")
                field_node = node.child_by_field_name("field")
                if base_node and field_node:
                    base_name = line[base_node.start_byte:base_node.end_byte]
                    field_name = line[field_node.start_byte:field_node.end_byte]
                    operator = next((c for c in node.children if c.type in ["->", "."]), None)
                    if operator:
                        full_name = f"{base_name}{line[operator.start_byte:operator.end_byte]}{field_name}"
                        var_value = get_most_recent_value(full_name, current_lineno)
                        variables[full_name] = var_value if var_value else "NULL"
                return
            
            # Handle binary expressions (>, ==, etc.)
            if node.type in ["binary_expression", "comparison_expression"]:
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left:
                    collect(left)
                if right:
                    collect(right)
                return
            
            # Default case: recurse through children
            for child in node.children:
                collect(child)
        
        collect(node)
        return variables

    while stack:
        node = stack.pop()
        
        # Handle if statements
        # if node.type == "if_statement":
        #     condition_node = node.child_by_field_name("condition")
        #     if condition_node and condition_node.type == "parenthesized_expression":
        #         condition_expr = condition_node.child(1)
        #         if condition_expr:
        #             condition_vars = collect_condition_variables(condition_expr)

                    
        #             if_line = line[condition_node.start_byte:condition_node.end_byte]
                    
        #             results.append({
        #                 "Programming Language": "C",
        #                 "Statement Type": "Branch",
        #                 "Source Code": code,
        #                 "Selected Statement": f"if {if_line}",
        #                 "Function Input": function_input,
        #                 "Variable Values Before Statement": condition_vars,
        #                 "Value After Statement Execution": "Yes" if executed else "No",
        #                 "Project Information": project_info
        #             })
        


        # Handle variable assignments (a = b;)
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            
            if left and right:
                var_name = line[left.start_byte:left.end_byte]
                var_value = get_most_recent_value(var_name, current_lineno)
                
                # Case 1: Right side is a variable (identifier)
                if right.type == "identifier":
                    rhs_var = line[right.start_byte:right.end_byte]
                    rhs_value = get_most_recent_value(rhs_var, current_lineno)
                    
                    if rhs_value and isinstance(rhs_value, str):
                        if re.match(r'^0x[0-9a-fA-F]+\s', rhs_value):
                            rhs_value = rhs_value.split(' ', 1)[-1]
                    else:
                        rhs_value = "NULL"
                    results.append({
                        "Programming Language": "C",
                        "Source Code": code,
                        "Selected Statement": line.strip(),
                        "Function Input": function_input,
                        "Variable Values Before Statement": {
                            rhs_var: rhs_value if rhs_value else "NULL"
                        },
                        "Value After Statement Execution": rhs_value if rhs_value else "NULL",
                        "Block_Size": block_size,
                        "Project Information": project_info 
                    })
                
                # Case 2: Right side is a literal (constant)
                elif right.type in ["number_literal", "string_literal"]:
                    const_value = line[right.start_byte:right.end_byte]
                    
                    results.append({
                        "Programming Language": "C",
                        "Source Code": code,
                        "Selected Statement": line.strip(),
                        "Function Input": function_input,
                        "Variable Values Before Statement": {
                            "constant": const_value
                        },
                        "Value After Statement Execution": const_value,
                        "Block_Size": block_size,
                        "Project Information": project_info 
                    })
                
                # Case 3: Right side is an arithmetic expression
                elif right.type == "binary_expression":
                    lhs_post_value = get_post_recent_value(var_name, current_lineno)
                    variables_in_expr = {}
                    
                    def collect_variables(node):
                        if node.type == "identifier":
                            var_name = line[node.start_byte:node.end_byte]
                            var_value = get_most_recent_value(var_name, current_lineno)
                            variables_in_expr[var_name] = var_value if var_value else "NULL"
                        for child in node.children:
                            collect_variables(child)
                    
                    collect_variables(right)
                    
                    results.append({
                        "Programming Language": "C",
                        "Source Code": code,
                        "Selected Statement": line.strip(),
                        "Function Input": function_input,
                        "Variable Values Before Statement": variables_in_expr,
                        "Value After Statement Execution":lhs_post_value if lhs_post_value else "NULL",
                        "Block_Size": block_size,
                        "Project Information": project_info
                    })
                
                # Case 4: Right side is a function call (a = function(c,d))
                elif right.type == "call_expression":
                    function_name_node = right.child_by_field_name("function")
                    arguments_node = right.child_by_field_name("arguments")
                    
                    if function_name_node:
                        function_name = line[function_name_node.start_byte:function_name_node.end_byte]
                        parameters = {}
                        
                        # Collect all argument values
                        if arguments_node:
                            for child in arguments_node.children:
                                # Skip non-argument nodes (parentheses and commas)
                                if child.type in ["(", ")", ","]:
                                    continue
                                    
                                if child.type == "identifier":
                                    arg_name = line[child.start_byte:child.end_byte]
                                    arg_value = get_most_recent_value(arg_name, current_lineno)
                                    parameters[arg_name] = arg_value if arg_value else "NULL"
                                elif child.type in ["number_literal", "string_literal"]:
                                    const_value = line[child.start_byte:child.end_byte]
                                    parameters[const_value] = const_value
                                elif child.type == "field_expression": 
                                    base_node = child.child_by_field_name("argument")
                                    field_node = child.child_by_field_name("field")
                                    if base_node and field_node:
                                        base_name = line[base_node.start_byte:base_node.end_byte]
                                        field_name = line[field_node.start_byte:field_node.end_byte]
                                        operator = next((c for c in child.children if c.type in ["->", "."]), None)
                                        if operator:
                                            full_name = f"{base_name}{line[operator.start_byte:operator.end_byte]}{field_name}"
                                            arg_value = get_most_recent_value(full_name, current_lineno)
                                            parameters[full_name] = arg_value if arg_value else "NULL"
                        
                        assigned_value = get_most_recent_value(var_name, current_lineno)
                        
                        results.append({
                            "Programming Language": "C",
                            "Source Code": code,
                            "Selected Statement": line.strip(),
                            "Function Input": function_input,
                            "Variable Values Before Statement": parameters,
                            "Value After Statement Execution": assigned_value if assigned_value else "NULL",
                            "Function Name": function_name,
                            "Block_Size": block_size,
                            "Project Information": project_info
                        })
        
        elif node.type == "declaration":
            declarator = node.child_by_field_name("declarator")
            if declarator and declarator.type == "init_declarator":
                var_node = declarator.child_by_field_name("declarator")
                value_node = declarator.child_by_field_name("value")
                
                if var_node and value_node:
                    var_name = line[var_node.start_byte:var_node.end_byte]
                    var_value = get_most_recent_value(var_name, current_lineno)
                    
                    if value_node.type == "identifier":
                        rhs_var = line[value_node.start_byte:value_node.end_byte]
                        rhs_value = get_most_recent_value(rhs_var, current_lineno)
                        
                        results.append({
                            "Programming Language": "C",
                            "Source Code": code,
                            "Selected Statement": line.strip(),
                            "Function Input": function_input,
                            "Variable Values Before Statement": {
                                rhs_var: rhs_value if rhs_value else "NULL"
                            },
                            "Value After Statement Execution": rhs_value if rhs_value else "NULL",
                            "Block_Size": block_size,
                            "Project Information": project_info
                        })
                    
                    elif value_node.type in ["number_literal", "string_literal"]:
                        const_value = line[value_node.start_byte:value_node.end_byte]
                        
                        results.append({
                            "Programming Language": "C",
                            "Source Code": code,
                            "Selected Statement": line.strip(),
                            "Function Input": function_input,
                            "Variable Values Before Statement": {
                                "constant": const_value
                            },
                            "Value After Statement Execution": str(const_value),
                            "Block_Size": block_size,
                            "Project Information": project_info
                        })
                    
                    elif value_node.type == "binary_expression":
                        lhs_post_value = get_post_recent_value(var_name, current_lineno)
                        variables_in_expr = {}
                        
                        def collect_variables(node):
                            if node.type == "identifier":
                                var_name = line[node.start_byte:node.end_byte]
                                var_value = get_most_recent_value(var_name, current_lineno)
                                variables_in_expr[var_name] = var_value if var_value else "NULL"
                            for child in node.children:
                                collect_variables(child)
                        
                        collect_variables(value_node)
                        
                        results.append({
                            "Programming Language": "C",
                            "Source Code": code,
                            "Selected Statement": line.strip(),
                            "Function Input": function_input,
                            "Variable Values Before Statement": variables_in_expr,
                            "Value After Statement Execution": lhs_post_value if lhs_post_value else "NULL",
                            "Block_Size": block_size,
                            "Project Information": project_info
                        })
                    
                    elif value_node.type == "call_expression":
                        function_name_node = value_node.child_by_field_name("function")
                        arguments_node = value_node.child_by_field_name("arguments")
                        
                        if function_name_node:
                            function_name = line[function_name_node.start_byte:function_name_node.end_byte]
                            parameters = {}
                            
                            # Collect all argument values
                            if arguments_node:
                                for child in arguments_node.children:
                                    if child.type == "identifier":
                                        arg_name = line[child.start_byte:child.end_byte]
                                        arg_value = get_most_recent_value(arg_name, current_lineno)
                                        parameters[arg_name] = arg_value if arg_value else "NULL"
                                    elif child.type in ["number_literal", "string_literal"]:
                                        parameters[line[child.start_byte:child.end_byte]] = line[child.start_byte:child.end_byte]
                            
                            # Get the value assigned to the variable (after execution)
                            assigned_value = get_most_recent_value(var_name, current_lineno)
                            
                            results.append({
                                "Programming Language": "C",
                                "Source Code": code,
                                "Selected Statement": line.strip(),
                                "Function Input": function_input,
                                "Variable Values Before Statement": parameters,
                                "Value After Statement Execution": assigned_value if assigned_value else "NULL",
                                "Function Name": function_name,
                                "Block_Size": block_size,
                                "Project Information": project_info
                            })
        
        stack.extend(node.children)
    return results