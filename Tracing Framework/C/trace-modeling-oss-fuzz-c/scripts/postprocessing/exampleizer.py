import pprint
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict

from class_parser import *

import logging

log = logging.getLogger(__name__)


jar_code_dir = Path("jar_code")


def serialize_variable(node):
    """
    Represent a <variable> or sibling tag as a string.
    """
    # TODO: handle <SKIPPED>, <event-thread-mismatch>, <exception>
    if node.tag == "variable":
        text = node.text
        if node.attrib["serializer"] == "ARRAY":
            text = text.strip()
        elif node.attrib["serializer"] == "TOSTRING":
            if text.startswith('"') and text.endswith('"'):
                m = re.search(r"@[\da-z]{8}", text)
                if m is not None:
                    text = text[: m.start()] + text[m.end() :]
        if "age" in node.attrib:
            del node.attrib["age"]
        return {
            "tag": node.tag,
            **node.attrib,
            "text": text,
        }
    else:
        return {
            "tag": node.tag,
            **node.attrib,
            "xml": ET.tostring(node, encoding="unicode"),
        }


def serialize_tracepoint(method_node, node):
    """
    Convert <tracepoint> tag into dict.
    """
    variables = [serialize_variable(v) for v in node]
    result = {
        "tag": node.tag,
        **node.attrib,
        "variables": variables,
    }
    try:
        lineno = int(node.attrib["location"].split(":")[1])
        result.update({
            "relative_lineno": lineno - method_node.start_point[0],
            "lineno": lineno,
        })
    except IndexError:
        pass
    return result

auto_lookup = {
    # "org.springframework": "spring-framework",
    "org.slf4j": "slf4j-api",
    # "jakarta.mail": "jakarta-mail-api",
}


def get_src_fpath(project, class_name):
    """
    Get filepath of class_name source code.
    """
    fudged = False
    if class_name.endswith("Fuzzer") or class_name == "ExampleFuzzerNative":
        class_filepath = class_name.replace(".", "/")
        src_fpaths = list((Path("projects") / project).rglob(class_filepath + ".java"))
    else:
        src_fpaths = get_source_file(Path("repos_build") / project, class_name)
        src_fpaths += get_source_file(Path("repos") / project, class_name)
        # TODO: add jar_code directory as a fallback
    return src_fpaths, fudged


def get_dynamic_information(call, method_node):
    """
    Return a list of lines covered by the method.
    """

    steps = []
    entry_variables = None
    for child in call:
        if child.tag == "call":
            pass
        elif child.tag == "tracepoint":
            steps.append(child)
            if child.attrib["type"] == "entry":
                entry_variables = [serialize_variable(v) for v in child]
        else:
            steps.append(child)
    assert entry_variables is not None, f"malformed trace: {call}"

    steps_data = []
    for node in steps:
        if node.tag == "tracepoint":
            steps_data.append(serialize_tracepoint(method_node, node))
        else:
            steps_data.append(
                {
                    "tag": node.tag,
                    "text": node.text,
                    **node.attrib,
                }
            )
    # lines_covered = list(
    #     sorted(set(s["relative_lineno"] for s in steps_data if "relative_lineno" in s))
    # )
    lines_covered = [
        {
            "type": s["type"],
            "relative_lineno": s["relative_lineno"],
            "variables": [
                {
                    "name": v["name"],
                    "serializer": v["serializer"],
                    "source": v["source"],
                    "type": v["type"],
                    "text": v["text"],
                } for v in s["variables"] if v["tag"] == "variable"
            ]
        } for s in steps_data if "relative_lineno" in s
    ]

    return entry_variables, lines_covered


def get_entry_exit_lineno(call):
    entry_lineno = None
    exit_lineno = None
    for child in call:
        if child.tag == "tracepoint":
            if child.attrib["type"] == "entry":
                try:
                    entry_lineno = int(child.attrib["location"].split(":")[1])
                except IndexError:
                    pass
            if child.attrib["type"] == "exit":
                try:
                    exit_lineno = int(child.attrib["location"].split(":")[1])
                except IndexError:
                    pass
    return entry_lineno, exit_lineno


import re
def convert_filepath(fpath):
    return re.sub(r"^/src/[^/]+/", "", fpath)


def resolve_filepath(project, fpath):
    return Path("repos_build") / project / fpath


from pathlib import Path
def get_code(fpath):
    pass


def process_one(call, xml):
    """
    Process one <call> tag into dict representation with extra metadata.
    """
    logger.info("XML: {} has {} chars in <call> tag. attrib: {}", xml, len(call), call.attrib.keys())

    project, fuzzer = re.search(r"([^/]+)/([^/]+)/all/log.xml", str(xml)).groups()

    for k in ["calleefilename", "callfilename"]:
        call.attrib[k] = convert_filepath(call.attrib[k])

    callee_location = {k: call.attrib[k] for k in ('callee', 'calleeline', 'calleefilename')}
    caller_location = {k: call.attrib[k] for k in ('caller', 'callerline', 'callline', 'callfilename')}

    resolved_fpath = resolve_filepath(project, call.attrib["calleefilename"])
    logger.info("Resolve filepath: {} (exists={})", resolved_fpath, resolved_fpath.exists())
    code = get_code(resolved_fpath)

    return {
        "result": "success",
        "data": {
            "project": project,
            "fuzzer": fuzzer,
            "location": {
                "callee": callee_location,
                "caller": caller_location,
            }
        },
    }
    # try:
    #     lineno = int(call.attrib["location"].split(":")[1])
    # except IndexError:
    #     lineno = None
    # method = call.attrib["method"]
    # location = decompose_location(method)
    # if location["method_name"].startswith("$"):
    #     return {
    #         "result": "invalid_call",
    #         "xml": str(xml),
    #         "class_name": location["class_name"],
    #         "method_name": location["method_name"],
    #         "method": method,
    #         "location": location,
    #         # "call_xml": ET.tostring(call).decode(),
    #     }
    # if location["inner_class_name"] is not None:
    #     return {
    #         "result": "skipped_inner_class",
    #         "xml": str(xml),
    #         "method": method,
    #         "location": location,
    #     }
    # if location["method_name"].startswith("lambda$"):
    #     return {
    #         "result": "skipped_lambda",
    #         "xml": str(xml),
    #         "method": method,
    #         "location": location,
    #     }
    # class_name = location["class_name"]

    # entry_lineno, exit_lineno = get_entry_exit_lineno(call)

    # xml_stem = xml.stem
    # project_fuzzer = xml_stem.split("-", maxsplit=1)[1]
    # project, fuzzer_name = project_fuzzer.rsplit("-", maxsplit=1)
    # method_name = location["method_name"]
    # parameter_types = location["parameter_types"]
    # try:
    #     src_fpaths, fudged = get_src_fpath(project, class_name)
    #     if len(src_fpaths) == 0:
    #         return {
    #             "result": "missing_source",
    #             "xml": str(xml),
    #             "project": project,
    #             "class_name": class_name,
    #             "method": method,
    #             "location": location,
    #         }
    #     method_node = None
    #     for fpath in src_fpaths:
    #         method_node = get_method_node(fpath, class_name, method_name, lineno, entry_lineno, parameter_types)
    #         if method_node is not None:
    #             break

    #     if method_node is None:
    #         return {
    #             "result": "missing_method",
    #             "project": project,
    #             "class_name": class_name,
    #             "method_name": method_name,
    #             "lineno": lineno,
    #             "entry_lineno": entry_lineno,
    #             "parameter_types": parameter_types,
    #             "all_src_fpath": [str(fpath) for fpath in src_fpaths],
    #             "xml": str(xml),
    #             # "call_xml": ET.tostring(call).decode(),
    #         }

    #     assert method_node is not None, method_node
    #     method_type = get_method_type(method_node)
    #     method_code = method_node.text.decode()

    #     entry_variables, lines_covered = get_dynamic_information(call, method_node)

    #     return {
    #         "result": "success",
    #         "data": {
    #             "project": project,
    #             "class": class_name,
    #             "method": method_name,
    #             "lineno": lineno,
    #             "entry_lineno": entry_lineno,
    #             "parameter_types": parameter_types,
    #             "src_fpath": str(fpath),
    #             "all_src_fpath": [str(fpath) for fpath in src_fpaths],
    #             "fudged_repo": fudged,
    #             "method_type": method_type,
    #             "is_forward": method_type == "forward",
    #             "has_body": method_type != "no_body",
    #             "xml_file_path": str(xml.absolute()),
    #             "file_path": str(fpath.absolute()),
    #             "start_point": method_node.start_point,
    #             "end_point": method_node.end_point,
    #             "code": method_code,
    #             "entry_variables": entry_variables,
    #             "attributes": call.attrib,
    #             "lines_covered": lines_covered,
    #         },
    #     }
    # except Exception as ex:
    #     log.exception(f"ERROR HANDLING METHOD {project=} {class_name=} {method_name=}")
    #     return {
    #         "result": "error_method",
    #         "project": project,
    #         "class_name": class_name,
    #         "method_name": method_name,
    #         "ex": str(traceback.format_exc()),
    #     }

    
def test_process_no_lineno():
    print()
    xml = Path("postprocessed_xmls/trace-java-example-ExampleFuzzerNative.xml")
    it = (n for _, n in ET.iterparse(xml) if n.tag == "call")
    results = defaultdict(int)
    for node in it:
        data = process_one(node, xml)
        results[data["result"]] += 1
        # pprint.pprint(data)
    pprint.pprint(dict(results))
    
def test_process_one():
    print()
    xml = Path("postprocessed_xmls/trace-greenmail-UserManagerFuzzer.xml")
    it = (n for _, n in ET.iterparse(xml) if n.tag == "call")

    myp = pprint.PrettyPrinter(width=600)

    i = 0
    results = defaultdict(int)
    fudged = []
    for node in it:
        try:
            data = process_one(node, xml)
            results[data["result"]] += 1
            if data["result"] != "success":
                print(i, "MISSING!")
                myp.pprint(data)
                # break
            else:
                fudged.append(data["data"]["fudged_repo"])
            # myp.pprint(data)
        except Exception:
            print(i, "FAILED!")
            traceback.print_exc()
            break
        i += 1
    myp.pprint(dict(results))
    print("FUDGED:", sum(fudged), len(fudged))
