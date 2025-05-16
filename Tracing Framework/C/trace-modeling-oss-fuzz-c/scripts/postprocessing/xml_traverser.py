import xml.etree.ElementTree as ET
import tqdm
import logging
from multiprocessing import Pool
log = logging.getLogger(__name__)

def count_calls(xml):
    """Return the number of <call> tags in xml."""
    num_calls = 0
    with open(xml) as inf:
        for line in tqdm.tqdm(inf, desc="count <call> tags", leave=False):
            if "<call" in line:
                num_calls += 1
    return num_calls


def enumerate_calls(xml):
    """Return a generator yielding all <call> nodes in xml."""
    it = ET.iterparse(xml, events=("end",))
    try:
        for _, node in it:
            if node.tag == "call":
                yield node
                node.clear()
    except ET.ParseError as ex:
        log.error(f"XML file ended prematurely. {ex}")

