from .prompt_template import PROMPT_REGISTRY
  

def generate_cot_steps(args, sample):
    def get_template(template_type):
        template_type = template_type.lower().replace(" ", "_")
        return PROMPT_REGISTRY[f"pt{args.pt_id}"].get(template_type)
    
    if args.prediction == "statement":
        st_type = sample['Statement Type']
        variables = sample['Variable Values Before Statement']
        statement = sample['Selected Statement']
        
        if st_type in ['Assignment', 'Constant Assignment', 'Arithmetic Assignment']:
            cot_assignment_template = get_template("assignment_cot")
            return cot_assignment_template.format(
                statement = statement,
                variables = variables,
            )
        elif st_type == "Branch":
            cot_branch_template = get_template("branch_cot")
            return cot_branch_template.format(
                statement = statement,
                variables = variables,
            )
        elif st_type == "API":
            cot_api_template = get_template("api_cot")
            return cot_api_template.format(
                statement = statement,
                variables = variables,
            )
    elif args.prediction in ["input", "output"]:
        cot_io_template = get_template(f"{args.prediction}_cot")
        
        if args.prediction == "input":
            return cot_io_template.format(
                output = sample['output']                
            )
        else:
            return cot_io_template.format(
                input = sample['input']                
            ) 
    elif args.prediction == "block":
        cot_io_template = get_template(f"{args.prediction}_cot")
        return cot_io_template.format(
            statement = sample['Selected Statement'],
            input = sample['Function Input']
        )

    elif args.prediction == "loop":
        if args.settings == "iteration":
            cot_io_template = get_template("loop_iteration_cot")
        elif args.settings in ["body", "final"]:
            cot_io_template = get_template("loop_body_cot")
        elif args.settings == "after":
            cot_io_template = get_template("post_loop_analysis_cot")
        return cot_io_template.format()
    

def incontext_prompt_generator(args, demos):
    def get_template(template_type):
        template_type = template_type.lower().replace(" ", "_")
        return PROMPT_REGISTRY[f"pt{args.pt_id}"].get(template_type)
    
    if args.prediction == "statement":
        msg = get_template("statement_msg")
        msg = msg.format(
            lang=args.language.lower(),
            shot=args.shot
        )
        if args.CoT == "no":
            for i, sample in enumerate(demos, 1):
                if sample['Statement Type'] in ['Assignment', 'Constant Assignment', 'Arithmetic Assignment']:
                    template = get_template("assignment")
                else:
                    template = get_template(sample['Statement Type'])
                example = template.format(
                    lang=sample['Programming Language'].lower(),
                    code=sample['Source Code'],
                    statement=sample['Selected Statement'],
                    variables=sample['Variable Values Before Statement']
                )
                msg += f"EXAMPLE {i}:\n{example}\n"
                if args.quantized_prediction == "yes" and sample['Statement Type']!="Branch":
                    mapping_rules = sample['mapping_info']
                    
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    
                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Correct Answer:<ans>{sample['quantized value']}</ans>\n"
                else:
                    msg += f"Correct Answer:<ans>{sample['Value After Statement Execution']}</ans>\n"
            
            msg += (
                "\nNow, please solve the following new problem.\n\n"
            )
        else:
            msg += f"Here are {args.shot} worked examples with reasoning steps:\n\n"
            for i, sample in enumerate(demos, 1):
                if sample['Statement Type'] in ['Assignment', 'Constant Assignment', 'Arithmetic Assignment']:
                    template = get_template("assignment")
                else:
                    template = get_template(sample['Statement Type'])
                
                example = template.format(
                    lang=sample['Programming Language'].lower(),
                    code=sample['Source Code'],
                    statement=sample['Selected Statement'],
                    variables=sample['Variable Values Before Statement']
                )
                
                msg += f"EXAMPLE {i}:\n{example}\n"
                
                cot_steps = generate_cot_steps(args,sample)
                msg += f"Let's think step by step:\n{cot_steps}\n"
                if args.quantized_prediction == "yes" and sample['Statement Type']!="Branch":
                    mapping_rules = sample['mapping_info']
                    
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    
                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Therefore, the final answer is:<ans>{sample['quantized value']}</ans>\n"
                else:
                    msg += f"Therefore, the final answer is: <ans>{sample['Value After Statement Execution']}</ans>\n"
                msg += "----------------------------------------\n"
            
            msg += (
                "\nNow, please solve the following new problem. "
                "Think through each step carefully and put your final answer in <ans></ans> tags.\n\n"
            )

    elif args.prediction in ["input", "output"]:
        msg = get_template("input_output_msg")
        msg = msg.format(
            lang=args.language.lower(),
            shot=args.shot
        )
            
        if args.CoT == "no":
            for i, sample in enumerate(demos, 1):
                template = get_template(args.prediction)
                if args.prediction == "input":
                    example = template.format(
                        lang=args.language.lower(),
                        code=sample['code'],
                        output=sample['output'],
                )
                else:
                    example = template.format(
                        lang=args.language.lower(),
                        code=sample['code'],
                        input=sample['input'],
                )
                if args.prediction == "input":
                    gt = sample['input']
                else:
                    gt = sample['output']
                msg += f"EXAMPLE {i}:\n{example}\n"
                if args.quantized_prediction == "yes":
                    if args.prediction == "input":
                        mapping_rules = sample['input_mapping_info']
                        q_gt = sample['quantized_value_input']
                    else:
                        mapping_rules = sample['output_mapping_info']
                        q_gt = sample['quantized_value_output']
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    

                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Correct Answer:<ans>{q_gt}</ans>\n"
                else:
                    msg += f"Correct Answer:<ans>{gt}</ans>\n"
            
            msg += (
                "\nNow, please solve the following new problem.\n\n"
            )
        else:
            msg += f"Here are {args.shot} worked examples with reasoning steps:\n\n"
            
            for i, sample in enumerate(demos, 1):
                template = get_template(args.prediction)
                if args.prediction == "input":
                    example = template.format(
                        lang=args.language.lower(),
                        code=sample['code'],
                        output=sample['output'],
                )
                else:
                    example = template.format(
                        lang=args.language.lower(),
                        code=sample['code'],
                        input=sample['input'],
                )
                
                msg += f"EXAMPLE {i}:\n{example}\n"
                if args.prediction == "input":
                    gt = sample['input']
                else:
                    gt = sample['output']
                
                cot_steps = generate_cot_steps(args, sample)
                msg += f"Let's think step by step:\n{cot_steps}\n"
                if args.quantized_prediction == "yes":
                    if args.prediction == "input":
                        mapping_rules = sample['input_mapping_info']
                        q_gt = sample['quantized_value_input']
                    else:
                        mapping_rules = sample['output_mapping_info']
                        q_gt = sample['quantized_value_output']
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    

                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Therefore, the final answer is:<ans>{q_gt}</ans>\n"
                else:
                    msg += f"Therefore, the final answer is: <ans>{gt}</ans>\n"
                msg += "----------------------------------------\n"
            
            msg += (
                "\nNow, please solve the following new problem. "
                "Think through each step carefully and put your final answer in <ans></ans> tags.\n\n"
            )        
    elif args.prediction == "block":
        msg = get_template("block_msg")
        msg = msg.format(
            lang=args.language.lower(),
            shot=args.shot
        )
        template = get_template(args.prediction)
        if args.CoT == "no":
            for i, sample in enumerate(demos, 1):
                example = template.format(
                    lang=sample['Programming Language'].lower(),
                    code=sample['Source Code'],
                    statement=sample['Selected Statement'],
                    inputs=sample['Function Input']
                )
                msg += f"EXAMPLE {i}:\n{example}\n"
                if args.quantized_prediction == "yes":
                    mapping_rules = sample['mapping_info']
                    
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    
                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Correct Answer:<ans>{sample['quantized value']}</ans>\n"
                else:
                    msg += f"Correct Answer:<ans>{sample['Value After Statement Execution']}</ans>\n"
            
            msg += (
                "\nNow, please solve the following new problem.\n\n"
            )
        else:
            msg += f"Here are {args.shot} worked examples with reasoning steps:\n\n"
            for i, sample in enumerate(demos, 1):
                example = template.format(
                    lang=sample['Programming Language'].lower(),
                    code=sample['Source Code'],
                    statement=sample['Selected Statement'],
                    inputs=sample['Function Input']
                )
                
                msg += f"EXAMPLE {i}:\n{example}\n"
                
                cot_steps = generate_cot_steps(args,sample)
                msg += f"Let's think step by step:\n{cot_steps}\n"
                if args.quantized_prediction == "yes":
                    mapping_rules = sample['mapping_info']
                    
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    
                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Therefore, the final answer is:<ans>{sample['quantized value']}</ans>\n"
                else:
                    msg += f"Therefore, the final answer is: <ans>{sample['Value After Statement Execution']}</ans>\n"
                msg += "----------------------------------------\n"
            
            msg += (
                "\nNow, please solve the following new problem. "
                "Think through each step carefully and put your final answer in <ans></ans> tags.\n\n"
            )
    elif args.prediction == "loop":
        msg = get_template("loop_msg")
        msg = msg.format(
            lang=args.language.lower(),
            shot=args.shot
        )
        if args.settings == "iteration":
            template = get_template("loop_iteration")
        else:
            template = get_template("loop_body")
        if args.CoT == "no":
            for i, sample in enumerate(demos, 1):
                example = template.format(
                    lang = args.language.lower(),
                    code=sample['loop_code'],
                    question=sample['question']
                )
                msg += f"EXAMPLE {i}:\n{example}\n"
                if args.quantized_prediction == "yes":
                    mapping_rules = sample['mapping_info']
                    
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    
                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Correct Answer:<ans>{sample['quantized value']}</ans>\n"
                else:
                    msg += f"Correct Answer:<ans>{sample['answer']}</ans>\n"
            
            msg += (
                "\nNow, please solve the following new problem.\n\n"
            )
        else:
            msg += f"Here are {args.shot} worked examples with reasoning steps:\n\n"
            for i, sample in enumerate(demos, 1):
                example = template.format(
                    lang = args.language.lower(),
                    code=sample['loop_code'],
                    question=sample['question']
                )
                
                msg += f"EXAMPLE {i}:\n{example}\n"
                
                cot_steps = generate_cot_steps(args,sample)
                msg += f"Let's think step by step:\n{cot_steps}\n"
                if args.quantized_prediction == "yes":
                    mapping_rules = sample['mapping_info']
                    
                    rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
                    
                    msg += f"You have to give the value prediction using the given quantization rules:\n{rules_list}\n\n"
                    msg += f"Therefore, the final answer is:<ans>{sample['quantized value']}</ans>\n"
                else:
                    msg += f"Therefore, the final answer is: <ans>{sample['answer']}</ans>\n"
                msg += "----------------------------------------\n"
            
            msg += (
                "\nNow, please solve the following new problem. "
                "Think through each step carefully and put your final answer in <ans></ans> tags.\n\n"
            )
    return msg