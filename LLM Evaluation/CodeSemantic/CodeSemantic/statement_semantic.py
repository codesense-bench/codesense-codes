import numpy as np
from collections import defaultdict
import subprocess
from utils import (
    load_my_dataset,
    load_model,
    load_pt,
    save_jsonl,
    save_results_to_json,
    get_default_config
)
import torch
import argparse
from dataset_utils import select_shots_and_split_dataset
import json
import os

def normalize_value(value):
    if isinstance(value, str):
        value = value.strip().strip("'").strip('"')
        value = ' '.join(value.split())
    return str(value)

def evaluate_statement_based(res, args, model_name):
    is_correct = []
    type_correct = defaultdict(int)
    type_total = defaultdict(int)
    language = None

    dir_path = f"Detailed_Results/Prediction_{args.prediction}_{args.language}/Model_{model_name}/Shot_{args.shot}/"

    os.makedirs(dir_path, exist_ok=True)

    #We have selected pt_id 1 from our prompt validation
    file_path = f"{dir_path}Prompt_{args.pt_id}_CoT_{args.CoT}_incontext_{args.incontext}_quantization_{args.quantized_prediction}.jsonl"

    for d in res:
        try:
            language = d['ori_task']['Programming Language'].lower() 
            stmt_type = d['ori_task']['Statement Type']
            if args.quantized_prediction == "yes" and stmt_type!= "Branch":
                original_value = d['ori_task']['quantized value']
            else:
                original_value = d['ori_task']['Value After Statement Execution']
            
            if 'pred_ans' in d and len(d['pred_ans']) > 0:
                predicted_value = d['pred_ans'][0] if d['pred_ans'] else None
                
                #print(f"Original_Value:{original_value} vs Predicted_Value:{predicted_value}")

                if isinstance(original_value, str):
                    original_value = original_value.rstrip(';').strip().lower()
                if isinstance(predicted_value, str):
                    predicted_value = predicted_value.rstrip(';').strip().lower()
                    
                

                correct = normalize_value(original_value) == normalize_value(predicted_value)
                is_correct.append(correct)
                type_correct[stmt_type] += int(correct)
                type_total[stmt_type] += 1
            else:
                correct = False
                predicted_value = None
                is_correct.append(False)
                type_total[stmt_type] += 1

        
            with open(file_path, "a") as f:
                entry = {
                    "idx": d['ori_task']['idx'],
                    "prompt":d['input'],
                    "ground_truth": original_value,
                    "model_prediction": d['pred_text'],
                    "parsed_prediction": predicted_value,
                    "parsed_result": correct,
                }
                f.write(json.dumps(entry) + "\n")
        
        except KeyError as e:
            print(f"Warning: Missing key {e} in response for model {model.model_name}")
            is_correct.append(False)
            if 'stmt_type' in locals():
                type_total[stmt_type] += 1
        except RuntimeError as e:
            if 'CUDA out of memory' in str(e):
                print(f"CUDA out of memory error occurred - treating as incorrect answer")
                is_correct.append(False)
                if 'stmt_type' in locals():
                    type_total[stmt_type] += 1
                if hasattr(torch, 'cuda'):
                    torch.cuda.empty_cache()
            else:
                raise 

    overall_accuracy = np.mean(is_correct) if is_correct else 0.0
    type_accuracy = {t: type_correct[t]/type_total[t] if type_total[t] > 0 else 0.0 
                    for t in type_total}
    
    return overall_accuracy, type_accuracy, dict(type_total), language

def evaluate_block_based(res, args, model_name):
    block_results = defaultdict(lambda: {'correct': [], 'total': 0})
    language = None

    dir_path = f"Detailed_Results/Prediction_{args.prediction}_{args.language}/Model_{model_name}/Shot_{args.shot}/"

    os.makedirs(dir_path, exist_ok=True)

    #We have selected pt_id 1 from our prompt validation
    file_path = f"{dir_path}Prompt_{args.pt_id}_CoT_{args.CoT}_incontext_{args.incontext}_quantization_{args.quantized_prediction}.jsonl"

    for d in res:
        #print(d['input'])
        try:
            language = d['ori_task']['Programming Language'].lower()
            block_size = d['ori_task'].get('Block_Size', 1)
            
            if args.quantized_prediction == "yes":
                original_value = d['ori_task']['quantized value']
            else:
                original_value = d['ori_task']['Value After Statement Execution']
            

            if 'pred_ans' in d and len(d['pred_ans']) > 0:
                predicted_value = d['pred_ans'][0] if d['pred_ans'] else None
                
                if isinstance(original_value, str):
                    original_value = original_value.rstrip(';').strip().lower()
                if isinstance(predicted_value, str):
                    predicted_value = predicted_value.rstrip(';').strip().lower()
                
                
                correct = normalize_value(original_value) == normalize_value(predicted_value)
                block_results[block_size]['correct'].append(correct)
                block_results[block_size]['total'] += 1
            else:
                predicted_value = None
                correct = False
                block_results[block_size]['correct'].append(False)
                block_results[block_size]['total'] += 1
                
            with open(file_path, "a") as f:
                entry = {
                    "idx": d['ori_task']['idx'],
                    "prompt":d['input'],
                    "ground_truth": original_value,
                    "original_task": d['ori_task'],
                    "model_prediction": d['pred_text'],
                    "parsed_prediction": predicted_value,
                    "parsed_result": correct,
                    "block_size": d['ori_task']['Block_Size'],
                }
                f.write(json.dumps(entry) + "\n")
        except KeyError as e:
            print(f"Warning: Missing key {e}")
            block_results[block_size]['correct'].append(False)
            block_results[block_size]['total'] += 1
        except RuntimeError as e:
            if 'CUDA out of memory' in str(e):
                print("CUDA out of memory error - treating as incorrect")
                block_results[block_size]['correct'].append(False)
                block_results[block_size]['total'] += 1
                if hasattr(torch, 'cuda'):
                    torch.cuda.empty_cache()
            else:
                raise

    accuracy_results = {
        size: {
            'accuracy': np.mean(results['correct']) if results['correct'] else 0.0,
            'correct': sum(results['correct']),
            'total': results['total'],
        }
        for size, results in block_results.items()
    }
    
    overall_accuracy = np.mean([
        acc for size, results in block_results.items()
        for acc in results['correct']
    ]) if block_results else 0.0
    
    return overall_accuracy, accuracy_results, language

def evaluate_io_based(res, args, model_name):
    is_correct = []
    results = {
        'correct': 0,
        'total': 0,
        'examples': [],
    }
    language = args.language

    dir_path = f"Detailed_Results/Prediction_{args.prediction}_{args.language}/Model_{model_name}/Shot_{args.shot}/"

    os.makedirs(dir_path, exist_ok=True)

    #We have selected pt_id 1 from our prompt validation
    file_path = f"{dir_path}Prompt_{args.pt_id}_CoT_{args.CoT}_incontext_{args.incontext}_quantization_{args.quantized_prediction}.jsonl"

    for d in res:
        if language == "c":
            input_value = ""
            if args.prediction == "output":
                output_str = d['ori_task'].get('output', '{}')
                output_str = output_str.replace("'", '"')
                output_dict = json.loads(output_str)
                original_value = output_dict.get('value', '')
                
            elif args.prediction == "input":
                original_value = ""
                input_str = d['ori_task'].get('basic_input', '{}')
                
                try:
                    input_dict = json.loads(input_str.replace("'", "\""))
                except json.JSONDecodeError:
                    input_dict = {}

                if isinstance(input_dict, dict) and input_dict:
                    first_param_name = next(iter(input_dict.keys()), None)
                    if first_param_name:
                        param_data = input_dict.get(first_param_name, {})
                        original_value = param_data.get('value', '')
                    
        elif language == "java":
            if args.prediction == "output":
                output_list = d['ori_task'].get('output', '[]')
            
                original_values = [item.get('value', '') for item in output_list]

                original_value = original_values[0] if original_values else ''
                
            elif args.prediction == "input":
                input_values = []
                if isinstance(d['ori_task'].get('basic_input'), list) and d['ori_task']['basic_input']:
                    input_values = [param.get('value', '') for param in d['ori_task']['basic_input']]
                

                if len(input_values) > 1:
                    original_value = tuple(input_values)  
                elif len(input_values) == 1:
                    original_value = input_values[0]    
                else:
                    original_value = ''     
                
        elif language == "python":
            if args.quantized_prediction == "yes" and args.prediction == "input":
                original_value = d['ori_task'].get('quantized_value_input', '')
            elif args.quantized_prediction == "yes" and args.prediction == "output":
                original_value = d['ori_task'].get('quantized_value_output', '')
            elif args.quantized_prediction == "no" and args.prediction == 'input':
                original_value = d['ori_task'].get('input', '')
            elif args.quantized_prediction == "no" and args.prediction == 'output':
                original_value = d['ori_task'].get('output', '')
        try:
            if 'pred_ans' in d and len(d['pred_ans']) > 0:
                predicted_value = d['pred_ans'][0] if d['pred_ans'] else None
                # print(f"Original_Value:{original_value}")
                # print(f"Predicted_Value:{predicted_value}")

                if isinstance(original_value, str):
                    original_value = original_value.strip().lower()
                if isinstance(predicted_value, str):
                    predicted_value = predicted_value.strip().lower()

                correct = normalize_value(original_value) == normalize_value(predicted_value)
                is_correct.append(correct)
                results['correct'] += int(correct)
                results['total'] += 1
                
                results['examples'].append({
                    'correct': correct,
                    'expected': original_value,
                    'predicted': predicted_value,
                    'code': d['ori_task'].get('code', '')
                })
            else:
                predicted_value = None
                correct = False
                is_correct.append(False)
                results['total'] += 1
            with open(file_path, "a") as f:
                entry = {
                    "idx": d['ori_task']['idx'],
                    "prompt":d['input'],
                    "ground_truth": original_value,
                    "original_task": d['ori_task'],
                    "model_prediction": d['pred_text'],
                    "parsed_prediction": predicted_value,
                    "parsed_result": correct,
                }
                f.write(json.dumps(entry) + "\n")
                
        except KeyError as e:
            print(f"Warning: Missing key {e} in response")
            is_correct.append(False)
            results['total'] += 1
        except RuntimeError as e:
            if 'CUDA out of memory' in str(e):
                print("CUDA out of memory error - treating as incorrect")
                is_correct.append(False)
                results['total'] += 1
                if hasattr(torch, 'cuda'):
                    torch.cuda.empty_cache()
            else:
                raise

    overall_accuracy = np.mean(is_correct) if is_correct else 0.0
    return overall_accuracy, results, language


def evaluate_loop_based(res, args, model_name):
    is_correct = []
    results = {
        'correct': 0,
        'total': 0,
        'examples': [],
    }
    language = args.language
    
    dir_path = f"Detailed_Results/Prediction_{args.prediction}_{args.language}/Model_{model_name}/Shot_{args.shot}/"

    os.makedirs(dir_path, exist_ok=True)

    #We have selected pt_id 1 from our prompt validation
    file_path = f"{dir_path}Prompt_{args.pt_id}_CoT_{args.CoT}_incontext_{args.incontext}_settings_{args.settings}_quantization_{args.quantized_prediction}.jsonl"

    for d in res:
        try:
            if args.quantized_prediction == "yes":
                original_value = d['ori_task']['quantized value']
            else:
                original_value = d['ori_task']['answer']
            if 'pred_ans' in d and len(d['pred_ans']) > 0:
                predicted_value = d['pred_ans'][0] if d['pred_ans'] else None
                # print(f"original_value:{original_value}")
                # print(f"Prediction:{predicted_value}")

                if isinstance(original_value, str):
                    original_value = original_value.strip().lower()
                if isinstance(predicted_value, str):
                    predicted_value = predicted_value.strip().lower()

                correct = normalize_value(original_value) == normalize_value(predicted_value)
                
                is_correct.append(correct)
                results['correct'] += int(correct)
                results['total'] += 1
                
                results['examples'].append({
                    'correct': correct,
                    'expected': original_value,
                    'predicted': predicted_value,
                    'code': d['ori_task'].get('loop_code', '')
                })
            else:
                predicted_value = None
                correct = False
                is_correct.append(False)
                results['total'] += 1
                
            with open(file_path, "a") as f:
                entry = {
                    "idx": d['ori_task']['idx'],
                    "prompt":d['input'],
                    "ground_truth": original_value,
                    "original_task": d['ori_task'],
                    "model_prediction": d['pred_text'],
                    "parsed_prediction": predicted_value,
                    "parsed_result": correct,
                }
                f.write(json.dumps(entry) + "\n")
                
        except KeyError as e:
            print(f"Warning: Missing key {e} in response")
            is_correct.append(False)
            results['total'] += 1
        except RuntimeError as e:
            if 'CUDA out of memory' in str(e):
                print("CUDA out of memory error - treating as incorrect")
                is_correct.append(False)
                results['total'] += 1
                if hasattr(torch, 'cuda'):
                    torch.cuda.empty_cache()
            else:
                raise

    overall_accuracy = np.mean(is_correct) if is_correct else 0.0
    return overall_accuracy, results, language

def evaluate_alias_based(res, args, model_name):
    is_correct = []
    results = {
        'correct': 0,
        'total': 0,
        'examples': [],
    }
    language = args.language

    dir_path = f"Detailed_Results/Prediction_{args.prediction}_{args.language}/Model_{model_name}/Shot_{args.shot}/"

    os.makedirs(dir_path, exist_ok=True)

    #We have selected pt_id 1 from our prompt validation
    file_path = f"{dir_path}Prompt_{args.pt_id}_CoT_{args.CoT}_incontext_{args.incontext}_quantization_{args.quantized_prediction}.jsonl"

    for d in res:
        original_value = d['ori_task'].get('Aliasing', '')
        try:
            if 'pred_ans' in d and len(d['pred_ans']) > 0:
                predicted_value = d['pred_ans'][0] if d['pred_ans'] else None

                if isinstance(original_value, str):
                    original_value = original_value.strip().lower()
                if isinstance(predicted_value, str):
                    predicted_value = predicted_value.strip().lower()

                correct = original_value == predicted_value
                is_correct.append(correct)
                results['correct'] += int(correct)
                results['total'] += 1
                
                results['examples'].append({
                    'correct': correct,
                    'expected': original_value,
                    'predicted': predicted_value,
                    'code': d['ori_task'].get('Source Code', '')
                })
            else:
                is_correct.append(False)
                original_value = False
                correct = False
                predicted_value = None
                results['total'] += 1
                
            with open(file_path, "a") as f:
                entry = {
                    "idx": d['ori_task']['idx'],
                    "prompt":d['input'],
                    "ground_truth": original_value,
                    "original_task": d['ori_task'],
                    "model_prediction": d['pred_text'],
                    "parsed_prediction": predicted_value,
                    "parsed_result": correct,
                }
                f.write(json.dumps(entry) + "\n")
                
        except KeyError as e:
            print(f"Warning: Missing key {e} in response")
            is_correct.append(False)
            results['total'] += 1
        except RuntimeError as e:
            if 'CUDA out of memory' in str(e):
                print("CUDA out of memory error - treating as incorrect")
                is_correct.append(False)
                results['total'] += 1
                if hasattr(torch, 'cuda'):
                    torch.cuda.empty_cache()
            else:
                raise

    overall_accuracy = np.mean(is_correct) if is_correct else 0.0
    return overall_accuracy, results, language

def evaluate_conditional_based(res, args, model_name):
    is_correct = []
    results = {
        'correct': 0,
        'total': 0,
        'examples': [],
    }
    language = args.language

    dir_path = f"Detailed_Results/Prediction_{args.prediction}_{args.language}/Model_{model_name}/Shot_{args.shot}/"

    os.makedirs(dir_path, exist_ok=True)

    #We have selected pt_id 1 from our prompt validation
    file_path = f"{dir_path}Prompt_{args.pt_id}_CoT_{args.CoT}_incontext_{args.incontext}_quantization_{args.quantized_prediction}.jsonl"

    for d in res:
        original_value = d['ori_task'].get('answer', '')
        try:
            if 'pred_ans' in d and len(d['pred_ans']) > 0:
                predicted_value = d['pred_ans'][0] if d['pred_ans'] else None

                if isinstance(original_value, str):
                    original_value = original_value.strip().lower()
                if isinstance(predicted_value, str):
                    predicted_value = predicted_value.strip().lower()

                correct = original_value == predicted_value
                is_correct.append(correct)
                results['correct'] += int(correct)
                results['total'] += 1
                
                results['examples'].append({
                    'correct': correct,
                    'expected': original_value,
                    'predicted': predicted_value,
                    'code': d['ori_task'].get('Source Code', '')
                })
            else:
                is_correct.append(False)
                correct = False
                predicted_value = False
                results['total'] += 1
                
            with open(file_path, "a") as f:
                entry = {
                    "idx": d['ori_task']['idx'],
                    "prompt":d['input'],
                    "ground_truth": original_value,
                    "original_task": d['ori_task'],
                    "model_prediction": d['pred_text'],
                    "parsed_prediction": predicted_value,
                    "parsed_result": correct,
                }
                f.write(json.dumps(entry) + "\n")
                
        except KeyError as e:
            print(f"Warning: Missing key {e} in response")
            is_correct.append(False)
            results['total'] += 1
        except RuntimeError as e:
            if 'CUDA out of memory' in str(e):
                print("CUDA out of memory error - treating as incorrect")
                is_correct.append(False)
                results['total'] += 1
                if hasattr(torch, 'cuda'):
                    torch.cuda.empty_cache()
            else:
                raise

    overall_accuracy = np.mean(is_correct) if is_correct else 0.0
    return overall_accuracy, results, language

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data_id', type=int, required=True, help='Dataset ID to use')
    parser.add_argument('--model_id', type=int, required=True, help='Model ID to evaluate')
    parser.add_argument('--pt_id', type=int, required=True, help='Prompt template ID')
    parser.add_argument('--language', type=str, default=None, help='Programming language filter')
    parser.add_argument('--prediction', type=str, choices=['statement','block','input', 'output', 'loop', 'alias', 'conditional'], 
                       default='value', help='What to predict and evaluate against')
    parser.add_argument('--settings', type=str, default='default', 
                       help='Additional settings for evaluation')
    parser.add_argument('--shot', type=int, default=0, required= True, 
                       help='Number of shots for prompt')
    parser.add_argument('--incontext', type= str, default='different',choices=['same','different'], required= True, 
                       help='incontext examples type')
    parser.add_argument('--CoT', type= str, default='no',choices=['yes','no'], required= True, 
                       help='Incontext with or without CoT')
    parser.add_argument('--quantized_prediction', type = str, default = 'no', choices=['yes','no'], required = True)
    
    return parser.parse_args()


def main():
    args = parse_arguments()
    config = get_default_config(args)
    dataset = load_my_dataset(args.data_id)
    model = load_model(args.model_id)
    model.init_ai_kwargs(config)
    
    incontext_example, remaining_dataset = select_shots_and_split_dataset(dataset, args)
    args.dataset = dataset 
    
    if args.incontext == "same":
        remaining_dataset = args.dataset

    
    pt = load_pt(args.pt_id, demos=incontext_example if args.shot > 0 else None, args=args)
    
    
    res = model.chat_batch(pt, remaining_dataset)
    
    
    
    if args.prediction == "statement":
        overall_accuracy, type_accuracy, type_total, language = evaluate_statement_based(res, args, model.model_name)
        print(overall_accuracy)
    
        dir_path = f"{args.prediction}_Accuracy_Results/"


        os.makedirs(dir_path, exist_ok=True)
        
        
        
        data_entry = {
            "Model": model.model_name,
            "Prediction": args.prediction,
            "Prompt": args.pt_id,
            "Incontext": args.incontext,
            "CoT": args.CoT,
            "shot": args.shot,
            "quantization": args.quantized_prediction,
            "accuracy": overall_accuracy,
            "type_accuracy": type_accuracy,
        }
        with open(f"{dir_path}{args.prediction}_{args.language}_results.jsonl", "a") as f:
            f.write(json.dumps(data_entry) + "\n")

            
        # save_results_to_json(
        #     args, model.model_name, args.pt_id, language, 
        #     overall_accuracy, type_accuracy, type_total
        # )
        
    
    if args.prediction in ("input", "output"):
        overall_accuracy, io_results, language = evaluate_io_based(res, args, model.model_name)

        print(overall_accuracy)
        dir_path = f"{args.prediction}_Accuracy_Results/"

        os.makedirs(dir_path, exist_ok=True)
        
        
        data_entry = {
            "Model": model.model_name,
            "Prediction": args.prediction,
            "Prompt": args.pt_id,
            "Incontext": args.incontext,
            "CoT": args.CoT,
            "shot": args.shot,
            "quantization": args.quantized_prediction,
            "accuracy": overall_accuracy,
        }

        with open(f"{dir_path}{args.prediction}_{args.language}_results.jsonl", "a") as f:
            f.write(json.dumps(data_entry) + "\n")
        
        # save_results_to_json(
        #     args, model.model_name, args.pt_id, language, 
        #     overall_accuracy, None, io_results
        # )
    elif args.prediction == "loop":
        overall_accuracy, loop_results, language = evaluate_loop_based(res, args, model.model_name)
        print(overall_accuracy)
        dir_path = f"{args.prediction}_Accuracy_Results/"

        os.makedirs(dir_path, exist_ok=True)
        
        data_entry = {
            "Model": model.model_name,
            "Prediction": args.prediction,
            "Prompt": args.pt_id,
            "Incontext": args.incontext,
            "CoT": args.CoT,
            "shot": args.shot,
            "quantization": args.quantized_prediction,
            "accuracy": overall_accuracy,
            "settings": args.settings,
        }

        with open(f"{dir_path}{args.prediction}_{args.language}_results.jsonl", "a") as f:
            f.write(json.dumps(data_entry) + "\n")
        
        #print(overall_accuracy)
        #print(loop_results)
        
        # save_results_to_json(
        #     args, model.model_name, args.pt_id, language, 
        #     overall_accuracy, None, loop_results
        # )
    elif args.prediction == "alias":
        overall_accuracy, loop_results, language = evaluate_alias_based(res, args, model.model_name)
        print(overall_accuracy)
        dir_path = f"{args.prediction}_Accuracy_Results/"

        os.makedirs(dir_path, exist_ok=True)
        
        data_entry = {
            "Model": model.model_name,
            "Prediction": args.prediction,
            "Prompt": args.pt_id,
            "Incontext": args.incontext,
            "CoT": args.CoT,
            "shot": args.shot,
            "quantization": args.quantized_prediction,
            "accuracy": overall_accuracy,
        }

        with open(f"{dir_path}{args.prediction}_{args.language}_results.jsonl", "a") as f:
            f.write(json.dumps(data_entry) + "\n")
            
    elif args.prediction == "conditional":
        overall_accuracy, conditional_results, language = evaluate_conditional_based(res, args, model.model_name)
        print(overall_accuracy)
        dir_path = f"{args.prediction}_Accuracy_Results/"

        os.makedirs(dir_path, exist_ok=True)
        
        data_entry = {
            "Model": model.model_name,
            "Prediction": args.prediction,
            "Prompt": args.pt_id,
            "Incontext": args.incontext,
            "CoT": args.CoT,
            "shot": args.shot,
            "quantization": args.quantized_prediction,
            "accuracy": overall_accuracy,
        }

        with open(f"{dir_path}{args.prediction}_{args.language}_results.jsonl", "a") as f:
            f.write(json.dumps(data_entry) + "\n")
        
        # save_results_to_json(
        #     args, model.model_name, args.pt_id, language, 
        #     overall_accuracy, None, loop_results
        # )
    
    elif args.prediction == "block":
        overall_accuracy, block_results, language = evaluate_block_based(res, args, model.model_name)
        print(overall_accuracy)

        dir_path = f"{args.prediction}_Accuracy_Results/"

        os.makedirs(dir_path, exist_ok=True)
        
        data_entry = {
            "Model": model.model_name,
            "Prediction": args.prediction,
            "Prompt": args.pt_id,
            "Incontext": args.incontext,
            "CoT": args.CoT,
            "shot": args.shot,
            "quantization": args.quantized_prediction,
            "accuracy": overall_accuracy,
            "block_accuracy": block_results,
        }

        with open(f"{dir_path}{args.prediction}_{args.language}_results.jsonl", "a") as f:
            f.write(json.dumps(data_entry) + "\n")
            
            
        print(f"Results for {model.model_name} (PT {args.pt_id}, {args.language}):")
        print(f"  Overall accuracy: {overall_accuracy:.2f}")
        for block_size, results in sorted(block_results.items()):
            print(f"  Block size {block_size}: {results['accuracy']:.2f} ({results['total']} samples)")

        # save_results_to_json(
        #     model.model_name, pt_id, language, 
        #     overall_accuracy, None, block_results,
        #     is_block_based=True
        # )
        
        # save_results_to_json(
        #     args, model.model_name, args.pt_id, language, 
        #     overall_accuracy, None, block_results
        # )
        


def clear_hf_cache():
    cache_path = "/home/XXX/.cache/huggingface/hub/*"
    try:
        subprocess.run(f"rm -rf {cache_path}", shell=True, check=True)
        print("✅ Hugging Face cache cleared successfully.")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to clear cache: {e}")

if __name__ == '__main__':
    main()
    # data_id = 4  
    # pt_id = 0   
    
    # for model_id in range(10, 17): 
    #     print(f"\n=== Running Model ID: {model_id} ===")
    #     main(data_id, model_id, pt_id)
    #     clear_hf_cache()