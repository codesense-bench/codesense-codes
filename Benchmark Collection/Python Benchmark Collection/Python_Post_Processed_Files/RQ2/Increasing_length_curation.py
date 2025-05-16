import json
import re
import tiktoken
from collections import defaultdict

def contains_complex_type(value):
    """Check if a string contains complex types."""
    complex_patterns = [
        r"<class '.*'>",
        r"<.*object at 0x[\da-f]+>",
        r"at 0x[\da-f]+",
        r"^\s*<",
    ]
    if isinstance(value, str):
        return any(re.search(pattern, value) for pattern in complex_patterns)
    return False

def token_filtering(source_code, function_input=None):
    """Check if source code + input is within token limit"""
    tokenizer = tiktoken.get_encoding("cl100k_base")
    
    code_tokens = tokenizer.encode(source_code)
    
    input_tokens = []
    if function_input:
        if isinstance(function_input, dict):
            input_str = json.dumps(function_input)
            input_tokens = tokenizer.encode(input_str)
        elif isinstance(function_input, str):
            input_tokens = tokenizer.encode(function_input)
    
    return len(code_tokens) + len(input_tokens) <= 2048

def clean_code(code, keep_comments=False):
    """Clean code with option to preserve comments"""
    lines = code.split('\n')
    cleaned_lines = []
    in_docstring = False
    
    for line in lines:
        stripped = line.strip()
        
        # Skip blank lines
        if not stripped:
            continue
            
        # Handle docstrings
        if stripped.startswith(('"""', "'''")):
            if in_docstring:
                in_docstring = False
                continue
            elif len(stripped) > 3 and stripped.endswith(stripped[:3]):
                continue
            else:
                in_docstring = True
                continue
        if in_docstring:
            continue
            
        if not keep_comments and '#' in line:
            line = line.split('#')[0].rstrip()
            if not line:
                continue
                
        cleaned_lines.append(line)
        
    return '\n'.join(cleaned_lines)

def get_state_info(scratchpad, n, source_lines):
    """Extract statement and state while maintaining line alignment"""
    scratch_lines = scratchpad.split('\n')
    
    if n >= len(source_lines):
        return None, None
    
    source_line = source_lines[n]
    scratch_line = scratch_lines[n] if n < len(scratch_lines) else source_line
    
    stripped = source_line.strip()
    control_keywords = ('if ', 'elif ', 'else:', 'try:', 'except ')
    loop_keywords = ('for ', 'while ', 'with ')
    if (stripped.startswith(control_keywords) or 
        any(kw in stripped for kw in loop_keywords)):
        return None, None
    
    state_match = re.search(r'# \[STATE\] (.*?) \[/STATE\]', scratch_line)
    if not state_match:
        return None, None
    

    clean_stmt = re.sub(r'# \[STATE\].*?\[/STATE\]', '', scratch_line).strip()
    state_value = state_match.group(1).strip()
    
    return clean_stmt, state_value

def process_file(input_file, output_file, n_values):
    stats = defaultdict(int)
    
    idx = 0
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            try:
                data = json.loads(line)
                # Clean source code (remove all comments)
                source_cleaned = clean_code(data['Source Code'])
                source_lines = source_cleaned.split('\n')
                
    
                if not token_filtering(source_cleaned, data.get('input')):
                    stats['token_limit_skipped'] += 1
                    continue
                
    
                scratchpad = data['scratchpad_format']
                
                for n in n_values:
                    statement, state = get_state_info(scratchpad, n, source_lines)
                    
                    if not statement or not state or contains_complex_type(state):
                        stats['complex_type_skipped'] += 1
                        continue
                    
                    # Safely handle state value splitting
                    try:
                        state_value = state.split("=", 1)[1].strip() if "=" in state else state
                    except:
                        state_value = state
                    
                    output_data = {
                        'idx': idx,
                        'Programming Language': data.get('Language', 'Python'),  # Changed key
                        'Source Code': source_cleaned,
                        'Selected Statement': statement,
                        "Function Input": data.get('input', {}),
                        'Value After Statement Execution': state_value,
                        'Variable States During Runtime': data.get('variable_values', {}),
                        'Block_Size': n,
                        'Program Information': f"Project Name: {data.get('Project_Name', 'unknown')}"
                    }
                    outfile.write(json.dumps(output_data) + '\n')
                    stats[f'n_{n}'] += 1
                    idx += 1
                    
            except (json.JSONDecodeError, KeyError) as e:
                stats['parse_errors'] += 1
                continue
    

    print("\nProcessing Statistics:")
    print(f"Skipped (token limit): {stats['token_limit_skipped']}")
    print(f"Skipped (complex types): {stats['complex_type_skipped']}")
    print(f"Parse errors: {stats['parse_errors']}")
    print("\nSamples per n value:")
    for n in n_values:
        print(f"n={n}: {stats.get(f'n_{n}', 0)}")
    print(f"\nTotal samples: {sum(v for k, v in stats.items() if k.startswith('n_'))}")

n_values = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
process_file('../dataset_all.jsonl', 'incremental_statement_prediction.jsonl', n_values)