from ..abst_pt import AbstPt
import sys
from .prompt_template import PROMPT_REGISTRY
from .prompting_utils import incontext_prompt_generator
sys.path.append('/home/XXX/CodeSemantic/CodeSemantic')
from dataset_utils import incontext_shots_with_same_statement
import json



class StatementPt1(AbstPt):
    def __init__(self, name, demos=None, args=None):
        super().__init__(name, demos or [])
        self.args = args
        self.demos = demos

    def get_template(self, template_type):
        template_type = template_type.lower().replace(" ", "_")
        return PROMPT_REGISTRY[f"pt{self.args.pt_id}"].get(template_type)


    def demo2msg(self, demos):
        msg = incontext_prompt_generator(self.args, demos)
        return msg
                
    def task2msg(self, task):
        pt =self.task2pt(task)
        msg = self._pt2msg(pt)
        return msg

    def task2pt(self, task: dict ):
        quantize_str = ""
        if self.args.incontext == "same":
            demos = incontext_shots_with_same_statement(self.args, task)
        else:
            demos = self.demos 
        
        if self.args.quantized_prediction == "yes":
            if self.args.prediction == "statement" or self.args.prediction == "block" or self.args.prediction == "loop":
                mapping_rules = task['mapping_info']
            elif self.args.prediction == "input":
                mapping_rules = task['input_mapping_info']
            elif self.args.prediction == "output":
                mapping_rules = task['output_mapping_info']
 
            rules_list = "\n".join([f"- {k} → {v}" for k, v in mapping_rules.items()])
            
            quantize_str += f"You MUST ONLY predict values that follow these quantization rules:\n{rules_list}.\nYour output MUST be one of the allowed quantized values.\n"

        if self.args.prediction == "output":
            pt = self.get_template(self.args.prediction)
            pt = pt.format(
                lang=self.args.language.lower(),
                code=task['code'],
                input= task['basic_input'][0] if self.args.language == "java" else task['input'],
                )
        elif self.args.prediction == "input":
            input_var = ""
            msg = ""
            if self.args.language.lower() == "c":
                basic_input = task.get('basic_input', {})
                if isinstance(basic_input, str):
                    try:
                        basic_input = json.loads(basic_input.replace("'", "\""))
                    except json.JSONDecodeError:
                        basic_input = {}

                if isinstance(basic_input, dict) and basic_input:
                    input_var = next(iter(basic_input.keys()), "")
                
                if input_var:
                    msg += f"Predict the value of input parameter {input_var} based on the given output.\n"
                    
            elif self.args.language.lower() == "java":
                if task.get('basic_input'):
                    input_vars = [item['name'] for item in task['basic_input']]
                    
                    if len(input_vars) > 1:
                        var_string = f"({', '.join(input_vars)})"
                        msg += f"Predict the values of input parameters {var_string} based on the given output.\n"
                    else:
                        msg += f"Predict the value of input parameter {input_vars[0]} based on the given output.\n"
                        
            pt = self.get_template(self.args.prediction)
            pt = pt.format(
                lang = self.args.language.lower(),
                code=task['code'],
                output=task['output'][0] if self.args.language == "java" else task['output'],
                )
            if msg and self.args.prediction == "input":
                lines = pt.split('\n')
                if lines:
                    lines.insert(-1, msg.strip())
                else:
                    lines = [msg.strip()]
                pt = '\n'.join(lines)
            else:
                pt = pt
                
        elif self.args.prediction == "loop":
            if self.args.settings == "iteration":
                pt = self.get_template("loop_iteration")
                pt = pt.format(
                    lang = self.args.language.lower(),
                    code=task['loop_code'],
                    question=task['question'],
                )
            elif self.args.settings == "body" or self.args.settings == "final" or self.args.settings == "after":
                pt = self.get_template("loop_body")
                pt = pt.format(
                    lang=self.args.language.lower(),
                    code=task['loop_code'],
                    question=task['question'],
                )
        elif self.args.prediction == "conditional":
            pt = self.get_template("conditional")
            pt = pt.format(
                lang = self.args.language.lower(),
                code=task['Source Code'],
                question=task['question'],
            )   
        elif self.args.prediction == "alias":
            pt = self.get_template(self.args.prediction)
            pt = pt.format(
                lang=self.args.language.lower(),
                code=task['Source Code'],
                input= task['Function Input'],
                pointer_1 = task['Selected Pointer'],
                line_1 = task['Selected Statement'],
                pointer_2 = task['Compared Pointer'],
            )
        elif self.args.prediction == "block":
            pt = self.get_template(self.args.prediction)
            pt = pt.format(
                lang=task['Programming Language'].lower(),
                code=task['Source Code'],
                statement=task['Selected Statement'],
                inputs=task['Function Input'],
            )
        elif self.args.prediction == "statement":
            if task['Statement Type'] == "Branch":
                pt = self.get_template("branch")
                pt = pt.format(
                        lang=task['Programming Language'].lower(),
                        code=task['Source Code'],
                        statement=task['Selected Statement'],
                        variables=task['Variable Values Before Statement'],
                    )
                quantize_str = ""
                        
            elif task['Statement Type'] == "API":
                pt = self.get_template("api")
                pt = pt.format(
                    lang=task['Programming Language'].lower(),
                    code=task['Source Code'],
                    statement=task['Selected Statement'],
                    variables=task['Variable Values Before Statement'],
                )
            else:
                pt = self.get_template("assignment")
                pt = pt.format(
                    lang=task['Programming Language'].lower(),
                    code=task['Source Code'],
                    statement=task['Selected Statement'],
                    variables=task['Variable Values Before Statement'],
                )
        if self.args.shot == 0:
            if self.args.quantized_prediction == "yes":
                pt = pt + "\n"+quantize_str
            else:
                pt = pt
        else:
            msg = self.demo2msg(demos)
            pt = msg + pt + "\n"+quantize_str

        # with open('/home/XXX/CodeSemantic/CodeSemantic/alias_prompt.txt', 'w') as f:
        #     f.write(pt)
        # print(pt)
        return pt

    def extract_ans(self, prompt_str, llm_output_str):
        return self.extract_data(llm_output_str, tag_name="ans")

    def _pt2msg(self, pt):
        msg = [{"content": pt, "role": "user"}]
        return msg


    def msg2pt(self):
        raise NotImplementedError




class StatementPt2(StatementPt1):
    def __init__(self, name, demos):
        super().__init__(name, demos)

    def task2pt(self, task: dict ):
        ori_code = task['Source Code']
        selected_statement = task['Selected Statement']
        val_dict = task['Variable Values Before Statement']
        val_str = ','.join([f"{k}={val_dict[k]}" for k in val_dict])
        ori_code_st_list = ori_code.split("\n")
        new_code_st_list = []
        for ori_st in ori_code_st_list:
            if ori_st.strip() == selected_statement.strip():
                new_v_str = val_str.replace("\n", ",")
                new_code_st_list.append(ori_st + f'# {new_v_str}')
            else:
                new_code_st_list.append(ori_st)
        new_code = "\n".join(new_code_st_list)
        if task['Statement Type'] == "Branch":
            pt = self.pt_template_branch.format(
                lang=task['Programming Language'].lower(),
                code=new_code,
                statement=task['Selected Statement'],
                variables=task['Variable Values Before Statement'],
            )
        elif task['Statement Type'] == "API":
            pt = self.pt_template_api.format(
                lang=task['Programming Language'].lower(),
                code=new_code,
                statement=task['Selected Statement'],
                variables=task['Variable Values Before Statement'],
            )
        else:
            pt = self.pt_template_assignment.format(
                lang=task['Programming Language'].lower(),
                code=new_code,
                statement=task['Selected Statement'],
                variables=task['Variable Values Before Statement'],
            )
        return pt

class StatementPt3(StatementPt1):
    def __init__(self, name, demos):
        super().__init__(name, demos)

    def task2pt(self, task: dict):
        ori_code = task['Source Code']
        new_code = ori_code
        pt = self.pt_template.format(
            lang=task['Programming Language'].lower(),
            code=new_code,
            statement=task['Selected Statement'],
            variables=task['Variable Values Before Statement'],
        )
        return pt