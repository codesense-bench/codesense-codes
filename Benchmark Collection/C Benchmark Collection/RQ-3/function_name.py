import tree_sitter
from tree_sitter_languages import get_parser


def extract_complete_function(source_code, target_function_name):
    """
    Extracts a complete C function using Tree-sitter parser.
    
    Args:
        source_code (str): Complete C source code
        target_function_name (str): Name of function to extract
        
    Returns:
        str: Complete function code or None if not found
    """
    parser = get_parser("c")
    tree = parser.parse(source_code.encode())
    
    functions = {}
    queue = [tree.root_node]
    
    while queue:
        node = queue.pop(0)
        
        # Check for function definition
        if node.type == "function_definition":
            # Get function declarator and name
            function_declarator = node.child_by_field_name("declarator")
            if function_declarator:
                # Handle different declarator types
                name_node = None
                if function_declarator.type == "function_declarator":
                    name_node = function_declarator.child_by_field_name("declarator")
                elif function_declarator.type == "identifier":
                    name_node = function_declarator
                
                # Extract function name if available
                if name_node and name_node.type == "identifier":
                    current_name = name_node.text.decode()
                    
  
                    functions[current_name] = {
                        'node': node,
                        'text': source_code[node.start_byte:node.end_byte]
                    }
        
 
        queue.extend(node.children)
    

    if target_function_name in functions:
        return functions[target_function_name]['text']
    
    return None

