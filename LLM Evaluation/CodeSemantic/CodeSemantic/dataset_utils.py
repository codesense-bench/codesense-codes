import random
from typing import Tuple, List, Dict


RANDOM_SEED = 42 
random.seed(RANDOM_SEED)

def select_shots_and_split_dataset(
    dataset: List[Dict], 
    args, 
    shot_key: str = 'Source Code',
    min_length_key: str = 'Source Code',
    min_code_length: int = 6
) -> Tuple[List[Dict], List[Dict]]:
    """
    Deterministic version that returns the same shots each time.
    """
    if args.shot == 0:
        return [], dataset
    
 
    if args.prediction == 'loop':
        min_length_key = 'loop_code'
        shot_key = 'loop_code'
    elif args.prediction in ["input", "output"]:
        min_length_key = 'code'
        shot_key = 'code'
    else:
        min_length_key = 'Source Code'
        shot_key = 'Source Code'
    

    valid_examples = [
        d for d in dataset 
        if min_length_key in d 
        and len(d[min_length_key]) >= min_code_length
    ]
    
    if not valid_examples:
        raise ValueError(
            f"No examples found with key '{min_length_key}' "
            f"and minimum length {min_code_length} in dataset"
        )
    

    sorted_examples = sorted(
        valid_examples,
        key=lambda x: (len(x[min_length_key]), hash(str(x)))
    )
    
    selected_shots = sorted_examples[:args.shot]
    
    remaining_dataset = [
        d for d in dataset 
        if d not in selected_shots
    ]
    
    return selected_shots, remaining_dataset

def incontext_shots_with_same_statement(args, query, min_code_length: int = 8):
    """Deterministic version that returns the same examples each time.
    Prioritizes examples with same Source Code but different IDX, fills remaining with others."""
    if args.shot == 0:
        return []
    
    if args.prediction == 'loop':
        min_length_key = 'loop_code'
    elif args.prediction in ["input", "output"]:
        min_length_key = 'code'
    else:  
        min_length_key = 'Source Code'
    
    if args.prediction == 'statement':
        query_type = query.get('Statement Type')
        type_key = 'Statement Type'
    elif args.prediction == 'block':
        query_type = query.get('Block_Size')
        type_key = 'Block_Size'
    else:
        query_type = None
        type_key = None
    

    selected_examples = []
    
    if args.prediction == "statement" or args.prediction == "block":
        if 'Source Code' in query and 'idx' in query:
            same_source_examples = [
                d for d in args.dataset 
                if 'Source Code' in d and 'idx' in d
                and d['Source Code'] == query['Source Code']
                and d['idx'] != query['idx']
            ]
            
            if same_source_examples:
                if len(same_source_examples) > args.shot:
                    selected_examples = same_source_examples[:args.shot]
                else:
                    selected_examples = same_source_examples

        remaining_shots = args.shot - len(selected_examples)
        if remaining_shots > 0:
            valid_examples = [
                d for d in args.dataset 
                if min_length_key in d
                and len(d[min_length_key]) >= min_code_length
                and d != query
                and (not query_type or str(d.get(type_key)) == str(query_type))
                and d not in selected_examples 
            ]
            
            if valid_examples:
                sorted_examples = sorted(
                    valid_examples,
                    key=lambda x: (len(x[min_length_key]), hash(str(x)))
                )

                selected_examples.extend(sorted_examples[:remaining_shots])
    else:
        valid_examples = [
            d for d in args.dataset 
            if min_length_key in d
            and len(d[min_length_key]) >= min_code_length
            and d != query
            ]
        sorted_examples = sorted(
            valid_examples,
            key=lambda x: (len(x[min_length_key]), hash(str(x)))
        )
        selected_examples = sorted_examples[2:(args.shot+2)]
        

    
    if not selected_examples:
        raise ValueError(
            f"No matching in-context examples found (type: {query_type}, " 
            f"min_length_key: {min_length_key}, "
            f"min_length: {min_code_length})"
        )
    
    return selected_examples