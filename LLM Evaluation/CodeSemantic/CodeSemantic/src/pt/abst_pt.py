
import re


class AbstPt:
    def __init__(self, name, demos):
        self.name = name
        self.demos = demos
        self.pt_template = None

    def task2msg(self, task):
        raise NotImplementedError

    def task2pt(self, task):
        raise NotImplementedError

    def extract_ans(self, prompt_str, llm_output_str):
        raise NotImplementedError

    def _pt2msg(self, pt):
        raise NotImplementedError


    def msg2pt(self, msg):
        raise NotImplementedError

    @staticmethod
    def extract_data(text, tag_name):

        # Regular expression to extract content within <scenario> tags
        pattern = fr"<{tag_name}>(.*?)</{tag_name}>"
        matches = re.findall(pattern, text, re.DOTALL)
        return matches