from typing import List
import time
import hashlib
import re
from abc import ABC, abstractmethod
from .utils import extract_tag
from ..pt.abst_pt import AbstPt

class AbstLLM(ABC):
    def __init__(self, provider, model):
        self.model = model
        self.provider = provider
        self.MAX_RETRIES = 3
        self.kwargs = {}

        self.ai_config = None
        self.temperature = None
        self.top_p = None
        self.max_tokens = None

        self.prefix_sym = None
        self.suffix_sym = None
        self.mid_sym = None
        self.mask_sym = None

        self.is_init = False
        self.stop = None
    def init_ai_kwargs(self, config):
        self.ai_config = config
        self.temperature = config['temperature']
        self.top_p = config['top_p']
        self.max_tokens = config['max_tokens']
        self.stop = config['stop']
        self.is_init = True

    @abstractmethod
    def chat_llm(self, messages):
        raise NotImplementedError

    @abstractmethod
    def competition_llm(self, prompts):
        raise NotImplementedError

    @abstractmethod
    def extract_text_logprobs(self, model_pred):
        raise NotImplementedError

    def chat_batch(self, pt: AbstPt, tasks: List[dict]):
        preproc = pt.task2msg
        postproc = pt.extract_ans
        query_func = self.chat_llm
        return self.gen_batch(tasks, preproc, postproc, query_func)

    def competition_batch(self, pt: AbstPt, tasks: List[dict]):
        preproc = pt.task2pt
        postproc = pt.extract_ans
        query_func = self.competition_llm
        return self.gen_batch(tasks, preproc, postproc, query_func)

    def gen_batch(self, tasks: List[dict], preproc, postproc, query_func):
        if not self.is_init: raise Exception("Gen Params is Not Init")

        input_list = [preproc(task) for task in tasks]
        t1 = time.time()
        outputs = query_func(input_list)
        t2 = time.time()
        cost_time = t2 - t1

        res = []
        for task, input_v, model_pred in zip(tasks, input_list, outputs):
            if model_pred is not None:
                pred_text, logits = self.extract_text_logprobs(model_pred)
            else:
                pred_text, logits = "", None
            llm_response = {
                'input': input_v,
                "ori_task": task,
                'model_pred': model_pred,
                "ai_config": self.ai_config,
                "pred_text": pred_text,
                "logits": logits,
                'pred_ans': postproc(input_v, pred_text),
                "cost_time": cost_time,
            }
            res.append(llm_response)
        return res


# class ChatProcess(ABC):
#     process_name = 'chat'
#
#     def _extract_code(self, task, pred_text):
#         match = re.search(r"```(?:\w+)?\n(.*?)\n```", pred_text, re.DOTALL)
#         return match.group(1) if match else ""
#
#     def _extract_testcase(self, llm_output, pred_text):
#         matches = extract_tag(pred_text, tag_name="test")
#         return matches[0] if matches else ""
#
#     def _task2code_gen_prompt(self, task: CodeGenTask) -> str:
#         # return self._lm_task2prompt(task)
#         prompt_template = \
#         ("You are a helpful coding assistant producing high-quality code. "
#          "Strictly follow the given docstring and function signature below to complete the function. "
#          "Your code should always gracefully return. Your response should include all dependencies, "
#          "headers and function declaration to be directly usable (even for the ones seen in the given part). "
#          "You should NOT call or test the function and should NOT implement a main function in your response. "
#          "You should implement the function in {lang}. "
#          "You should output your complete implementation in a single code block wrapped by triple backticks."
#          "\n\n\n"
#          "```{lang}\n"
#          "{code_prompt}\n"
#          "```\n\n\n"
#          "You should output your complete implementation in a single code block."
#          )
#         prompt = prompt_template.format(
#             lang=task.lang.lower(),
#             code_prompt=task.task_prompt)
#
#         return prompt
#
#     def _output2test_gen_prompt(self, llm_output: CodeGenLLMOutput):
#         suffix_str = \
#             ("Given the following Python code and function entry, generate a set of test cases to thoroughly test the "
#              "function.\n"
#              "Please ensure each test case is a `assert` statement\n"
#              "Format the output test cases inside `<test>` HTML tags for easy readability.\n\n"
#              "**Code:**\n"
#              "```python\n"
#              "{code_string}\n"
#              "```\n\n"
#              "**Function Entry:**\n"
#              "```\n"
#              "{func_name}\n"
#              "```")
#
#         suffix_str = suffix_str.format(
#             func_name=llm_output.original_task.entry_point,
#             code_string=llm_output.final_code)
#         return suffix_str
#
#
# class CompletionProcess(ABC):
#     process_name = 'completion'
#
#     def _task2code_gen_prompt(self, task: CodeGenTask) -> str:
#         return "```\n" + task.task_prompt
#
#     def _output2test_gen_prompt(self, llm_output: CodeGenLLMOutput):
#         suffix_str = ("if __name__ == '__main__':\n"
#                       "    assert {func_name}(")
#         suffix_str = suffix_str.format(func_name=llm_output.original_task.entry_point)
#         return llm_output.final_code + '\n\n' + suffix_str
#
#     def _extract_code(self, task, pred_text):
#         code = "```\n" + task.task_prompt + pred_text
#         match = re.search(r"```(?:\w+)?\n(.*?)\n```", code, re.DOTALL)
#         return match.group(1) if match else ""
#
#
#     def _extract_testcase(self, llm_output: CodeGenLLMOutput, pred_text):
#         code_str = llm_output.prompt_input + str(pred_text)
#         new_code_str = remove_last_line(code_str)
#         try:
#             test_case_str = extract_imports_and_asserts(new_code_str)
#         except:
#             test_case_str = ""
#         return test_case_str