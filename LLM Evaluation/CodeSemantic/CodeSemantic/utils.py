import json
from collections import defaultdict
from datasets import load_dataset
from src.codellm import AbstLiteLLM, LocalVLLM
from src.pt import StatementPt1, StatementPt2, StatementPt3
import os

def save_jsonl(data, filename):
    with open(filename, 'w') as f:
        for entry in data:
            serialized_entry = serialize_vllm_objects(entry)
            json.dump(serialized_entry, f)
            f.write('\n')

def load_existing_results(filename='all_results.json'):
    """Load existing results if file exists, otherwise return empty dict"""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_results_to_json(args, model_name, pt_id, language, overall_accuracy, 
                        type_accuracy, detailed_results):
    """Save results to JSON in Results folder, preserving existing data"""
    
    if args.prediction in ['input', 'output']:
        results_dir = 'Results_input_output_q' 
    else:
        results_dir = f'Results_{args.prediction}_q' 
    
    os.makedirs(results_dir, exist_ok=True)

    if args.prediction in ['input', 'output']:
        filename = "input_output_predictions.json"
    elif args.prediction == "loop":
        filename = "loop_predictions.json"
    elif args.prediction == "alias":
        filename = "alias_predictions.json"
    elif args.prediction == "block":
        filename = 'block_predictions.json'
    elif args.prediction == "statement":
        filename = 'statement_predictions.json'
    else:
        filename = 'all_results.json'
    
    results_path = os.path.join(results_dir, filename)
    existing_results = load_existing_results(results_path)
    
    shot = str(args.shot)
    quantized_key = f'quantized_{args.quantized_prediction}'
    
    if model_name not in existing_results:
        existing_results[model_name] = {}
        
    if quantized_key not in existing_results[model_name]:
        existing_results[model_name][quantized_key] = {}
    
    if f'pt{pt_id}' not in existing_results[model_name][quantized_key]:
        existing_results[model_name][quantized_key][f'pt{pt_id}'] = {}
    
    if language not in existing_results[model_name][quantized_key][f'pt{pt_id}']:
        existing_results[model_name][quantized_key][f'pt{pt_id}'][language] = {}
        
    if args.prediction not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language]:
        existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction] = {}
    

    if args.prediction in ['input', 'output']:
        shot_key = f"shot{args.shot}"
        if shot not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction]:
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key] = {}
            
        result_entry = {
            'overall_accuracy': overall_accuracy,
        }
        existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key] = result_entry
    
    elif args.prediction == "loop":
        if shot not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction]:
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot] = {}
        
        result_entry = {
            'overall_accuracy': overall_accuracy,
        }
        existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot][args.settings] = result_entry
    
    elif args.prediction == "alias":
        if shot not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language]:
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][shot] = {}
            
        result_entry = {
            'overall_accuracy': overall_accuracy,
        }
        existing_results[model_name][quantized_key][f'pt{pt_id}'][language][shot][args.prediction] = result_entry
    
    elif args.prediction == "block":
        result_entry = {
            'overall_accuracy': overall_accuracy,
            'block_results': detailed_results,
            'sample_counts': {
                size: results['total']
                for size, results in detailed_results.items()
            }
        }
        shot_key = f"shot{shot}"
        cot_key = f"CoT_{args.CoT}"
        incontext_key = f"Incontext_{args.incontext}"

        if shot_key not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction]:
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key] = {}
        
        if args.shot == 0:
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key] = result_entry
        else:
            if cot_key not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key]:
                existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key] = {}

            if incontext_key not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key]:
                existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key][incontext_key] = {}
            
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key][incontext_key] = result_entry
        
    elif args.prediction == "statement":
        result_entry = {
            'overall_accuracy': overall_accuracy,
            'type_accuracy': type_accuracy,
            'type_counts': detailed_results
        }
        shot_key = f"shot{shot}"
        cot_key = f"CoT_{args.CoT}"
        incontext_key = f"Incontext_{args.incontext}"

        if shot_key not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction]:
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key] = {}
        
        if args.shot == 0:
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key] = result_entry
        else:
            if cot_key not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key]:
                existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key] = {}

            if incontext_key not in existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key]:
                existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key][incontext_key] = {}
            
            existing_results[model_name][quantized_key][f'pt{pt_id}'][language][args.prediction][shot_key][cot_key][incontext_key] = result_entry
    
    with open(results_path, 'w') as f:
        json.dump(existing_results, f, indent=2)


def serialize_vllm_objects(obj):
    """Recursively convert VLLM objects to serializable formats"""
    if isinstance(obj, (str, int, float, bool)):
        return obj
    elif isinstance(obj, dict):
        return {key: serialize_vllm_objects(value) for key, value in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [serialize_vllm_objects(item) for item in obj]
    elif hasattr(obj, '__dict__'):
        return serialize_vllm_objects(obj.__dict__)
    else:
        return str(obj)

def serialize_response(response):
    """Convert non-serializable objects in the response to serializable formats"""
    serialized = {}
    for key, value in response.items():
        if key == 'model_pred':
            if hasattr(value, '__dict__'):
                serialized[key] = value.__dict__
            else:
                serialized[key] = str(value)
        else:
            serialized[key] = value
    return serialized

SPLIT_SYM = "____SPLIT____"

def load_my_dataset(data_id):
    if data_id == 0:
        with open("dataset/statement_prediction_dataset.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 1:
        with open("dataset/statement_prediction_dataset_C.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 2:
        with open("dataset/incremental_statement_prediction_python.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 3:
        with open("dataset/block_analysis_c.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 4:
        with open("dataset/incremental_statement_prediction_python_10.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 5:
        with open("dataset/input_output_dataset_python.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 6:
        with open("dataset/loop_iteration_dataset_python.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 7:
        with open("dataset/loop_body_dataset_python.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 8:
        with open("dataset/loop_final_dataset_python.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 9:
        with open("dataset/aliasing_dataset_c.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 10:
        with open("dataset/statement_prediction_dataset_python_quantized.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 11:
        with open("dataset/input_output_dataset_python_quantized.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 12:
        with open("dataset/incremental_statement_prediction_python_10_quantized.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 13:
        with open("dataset/loop_iteration_dataset_python_quantized.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 14:
        with open("dataset/loop_body_dataset_python_quantized.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 15:
        with open("dataset/loop_after_dataset_python_quantized.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 16:
        with open("dataset/input_output_dataset_c.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 17:
        with open("dataset/input_output_dataset_java.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 18:
        with open("dataset/conditional_dataset_python.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 19:
        with open("dataset/statement_prediction_dataset_python_quantized_200.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 20:
        with open("dataset/input_output_dataset_python_quantized_200.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 21:
        with open("dataset/statement_prediction_dataset_c_200.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 22:
        with open("dataset/incremental_statement_prediction_python_10_quantized_200.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    elif data_id == 23:
        with open("dataset/block_analysis_c_200.jsonl", 'r') as f:
            dataset = [json.loads(line) for line in f]
    else:
        raise NotImplementedError
    return dataset

# Model loading
def model_id2name_cls(model_id: int):
    model_map = {
        0: ("gemini-1.5-flash-002", AbstLiteLLM, "vertex_ai"),
        1: ("gemini-2.0-flash-lite-preview-02-05", AbstLiteLLM, "vertex_ai"),
        2: ("anthropic.claude-3-5-haiku-20241022-v1:0", AbstLiteLLM, "bedrock"),
        3: ("anthropic.claude-3-5-sonnet-20241022-v2:0", AbstLiteLLM, "bedrock"),
        4: ("deepseek-ai/deepseek-coder-1.3b-instruct", LocalVLLM, "openai"),
        5: ("Qwen/Qwen2.5-7B-Instruct", LocalVLLM, "openai"),
        6: ("microsoft/Phi-3-medium-128k-instruct", LocalVLLM, "openai"),
        7: ("meta-llama/Llama-3.1-8B-Instruct", LocalVLLM, "openai"),
        8: ("Qwen/Qwen2.5-14B-Instruct-1M", LocalVLLM, "openai"),
        9: ("Qwen/Qwen2.5-Coder-7B-Instruct", LocalVLLM, "openai"),
        10: ("deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct", LocalVLLM, "openai"),
        11: ("microsoft/Phi-4-mini-instruct", LocalVLLM, "openai"),
        12: ("microsoft/Phi-3.5-mini-instruct", LocalVLLM, "openai"),
        13: ("ibm-granite/granite-3.2-8b-instruct", LocalVLLM, "openai"),
        14: ("deepseek-ai/DeepSeek-R1-Distill-Qwen-7B", LocalVLLM, "openai"),
        15: ("deepseek-ai/DeepSeek-R1-Distill-Llama-8B", LocalVLLM, "openai"),
        16: ("deepseek-ai/DeepSeek-R1-Distill-Qwen-14B", LocalVLLM, "openai"),
        17: ("ibm-granite/granite-3.2-8b-instruct-preview", LocalVLLM, "openai"), 
        18: ("Qwen/Qwen3-8B", LocalVLLM, "openai"), 
        19: ("anthropic.claude-3-7-sonnet-20250219-v1:0", AbstLiteLLM, "bedrock" ),
        20: ("gpt-4o-mini", AbstLiteLLM, "openai"),
    }
    
    if model_id not in model_map:
        raise ValueError(f"Model ID {model_id} is not valid")
        
    model_name, model_cls, provider = model_map[model_id]
    return provider, model_name, model_cls, None, "chat_template/completation.jinjia"

def load_model(model_id):
    provider, model_name, model_cls, lora_path, chat_template_path = model_id2name_cls(model_id)
    model = model_cls(provider, model_name)
    model.model_name = model_name.split('/')[-1]
    return model

def load_pt(pt_id, demos=None, args=None):
    if demos is None:
        demos = []
    
    #from statementpt1 we are changing prompts based on different pt_ids
    return StatementPt1('pt1', demos=demos, args=args)
    # pt_map = {
    #     0: lambda: StatementPt1('pt1', demos=demos, args=args),
    #     1: lambda: StatementPt2('pt2', demos=demos, args=args),
    #     2: lambda: StatementPt3('pt3', demos=demos, args=args),
    # }
    
    # if pt_id not in pt_map:
    #     raise ValueError(f"PT ID {pt_id} is not valid")
    # return pt_map[pt_id]()  # Call the lambda to create instance


def get_default_config(args):
    config = {
        'temperature': 0.8,
        "top_p": 0.95,
        "max_tokens": 4096,  # Default value
        "tp_size": 1,
        "dtype": "float16",
        "stop": [
            "\n>>>", "\n$", '\nclass',
            '\ndef', '\n#', '\nprint',
            "\n@", "\nif __name__ == '__main__':"
        ]
    }

    if hasattr(args, 'model_id') and args.model_id in range(13, 18):
        config["max_tokens"] = 16392 

    return config
