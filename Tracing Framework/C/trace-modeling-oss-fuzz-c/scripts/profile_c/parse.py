#%%
# %load_ext autoreload
# %autoreload 2

#%%
from tree_sitter_utils import *
import json
from loguru import logger
from tree_sitter_languages import get_language, get_parser
import sys
import traceback

logger.remove()
logger.add(sys.stderr, level="ERROR")
logger.add(__file__ + ".log", mode="w", level="DEBUG")

language = get_language('c')
parser = get_parser('c')

#%%
class DFS:
    def __init__(self, root):
        self.results = []
        self.definitions = {}
        for n in self.traverse(root):
            self.process(n)
    
    def traverse(self, n):
        for c in n.children:
            yield from self.traverse(c)
        yield n
    
    def process(self, n):
        try:
            if n.type in ("if_statement", "while_statement", "do_statement"):
                reverse = n.type == "do_statement"
                parens = get_child(n, "parenthesized_expression", reverse=reverse)
                identifiers = get_ancestors(parens, "identifier")
                ids_text = [i.text.decode() for i in identifiers]
                self.results.append({
                    "type": n.type,
                    "start_point": n.start_point,
                    "end_point": n.end_point,
                    "condition": parens.text.decode(),
                    "id_types": {
                    i: self.definitions.get(i, None) for i in ids_text
                }})
            elif n.type in ("for_statement",):
                get_next = False
                first_child = None
                for c in n.children:
                    if get_next:
                        condition = c
                        break
                    else:
                        has_semicolon = get_ancestor_bfs(c, ";") is not None
                        first_child = c
                        if has_semicolon:
                            get_next = True
                identifiers = get_ancestors(condition, "identifier")
                ids_text = [i.text.decode() for i in identifiers]
                first_child_text = first_child.text.decode() if first_child.type != ";" else None
                self.results.append({
                    "type": n.type,
                    "start_point": n.start_point,
                    "end_point": n.end_point,
                    "condition": condition.text.decode(),
                    "init": first_child_text,
                    "id_types": {
                    i: self.definitions.get(i, None) for i in ids_text
                }})
                pass
            elif n.type in ("switch_statement",):
                parens = get_child(n, "parenthesized_expression")
                identifiers = get_ancestors(parens, "identifier")
                cases = get_ancestors(n, "case_statement")
                cases = list(cases)
                logger.debug("CASES: {}", cases)
                ids_text = [i.text.decode() for i in identifiers]
                def trim_case_code(code):
                    return code[:code.index(":")+1]
                self.results.append({
                    "type": n.type,
                    "start_point": n.start_point,
                    "end_point": n.end_point,
                    "condition": {
                        "parens": parens.text.decode(),
                        "case": [trim_case_code(c.text.decode()) for c in cases],
                    },
                    "id_types": {
                    i: self.definitions.get(i, None) for i in ids_text
                }})
            elif n.type in ("declaration", "parameter_declaration"):
                if get_child(n, "struct_specifier") is not None:
                    logger.debug("skipping {} because it declares a struct", n)
                    return
                typ = get_child(n, lambda x: x.type in ("primitive_type", "type_identifier", "sized_type_specifier")).text.decode()
                identifier = get_child(n, "identifier")
                if identifier is not None:
                    identifiers = [identifier.text.decode()]
                else:
                    identifiers = []
                    q = [n]
                    declarators = []
                    while len(q) > 0:
                        m = q.pop(0)
                        if m.type.endswith("_declarator"):
                            declarators.append(m)
                        else:
                            q.extend(reversed(m.children))
                    typ_suffix = None
                    for decl in declarators:
                        if decl.type == "pointer_declarator" and typ_suffix is None:
                            typ_suffix = "*" * len(list(get_ancestors(decl, "pointer_declarator")))
                        identifiers.append(get_ancestor(decl, "identifier").text.decode())
                    if typ_suffix is not None:
                        typ += typ_suffix
                for identifier in identifiers:
                    logger.debug("DECL: {}:{}", identifier, typ)
                    self.definitions[identifier] = typ
        except Exception:
            logger.warning("error processing node {} {}", n.type, n)
            print_tree(n, logger.warning)
            raise

def is_any_error(root):
    return any(n.type == "ERROR" for n in dfs(root))

def parse_c_file(fpath):
    try:
        logger.info("processing file {}...", fpath)
        with open(fpath, 'rb') as f:
            tree = parser.parse(f.read())
        if is_any_error(tree.root_node):
            logger.debug("skipping {} for error", fpath)
        print_tree(tree.root_node, logger.debug)
        dfs = DFS(tree.root_node)
    except Exception as e:
        logger.warning("error processing file {}\n{}", fpath, traceback.format_exc())
        return []
    return dfs.results

logger.debug("result: {}", json.dumps(parse_c_file("profile_c/test.c"), indent=2))

# %%
import glob
import tqdm
import os
import jsonlines

problems = list(sorted(glob.glob("/home/XXX/data/CodeNet/Project_CodeNet/data/*")))
logger.info("{} problems", len(problems))
logger.debug(problems)
# problems = problems[:1] # NOTE: debug
for problem in tqdm.tqdm(problems, position=0, desc="problems"):
    with jsonlines.open(os.path.join("profile_c_results", os.path.basename(problem) + ".jsonl"), "w") as writer:
        fpaths = list(sorted(glob.glob(problem + "/C/s*.c")))
        logger.info("{} paths in problem {}", len(fpaths), problem)
        logger.debug(fpaths)
        for fpath in tqdm.tqdm(fpaths, position=1, desc="files in problem"):
            writer.write({
                "fpath": fpath,
                "result": parse_c_file(fpath),
            })
