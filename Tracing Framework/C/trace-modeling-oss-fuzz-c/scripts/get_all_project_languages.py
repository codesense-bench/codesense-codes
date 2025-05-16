# langs = ["c", "c++"]
# langs = ["c++"]
# langs = ["c"]

import argparse
import yaml

def load_language_from_yaml(file_path):
    """
    Load the 'language' key from a YAML file.

    :param file_path: Path to the YAML file
    :return: The value of the 'language' key or None if not found
    """
    try:
        with open(file_path, 'r') as file:
            data = yaml.safe_load(file)
            return data.get('language')
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("langs", nargs="+")
args = parser.parse_args()
langs = args.langs

yamls = Path("projects").glob("*/project.yaml")
for fpath in yamls:
    project = fpath.parent.name
    lang = load_language_from_yaml(fpath)
    if lang in langs:
        print(project)
