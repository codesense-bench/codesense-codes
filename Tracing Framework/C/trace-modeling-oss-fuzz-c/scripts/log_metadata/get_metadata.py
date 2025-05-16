#%%
import yaml

def parse_yaml_file(fpath):
    # https://stackoverflow.com/a/1774043
    with open(fpath, "r") as stream:
        return yaml.safe_load(stream)

from pathlib import Path
projects = Path("projects")
project_dirs = list(projects.glob("*/"))
print(len(project_dirs), "projects in", projects.absolute())

all_data = []
for project in project_dirs:
    data = parse_yaml_file(project / "project.yaml")
    data["project"] = project.name
    all_data.append(data)

#%%
import pandas as pd
import json
df = pd.DataFrame(all_data)
df.assign(fuzzing_engines=df.fuzzing_engines.apply(json.dumps)).to_csv("data/all_project_data.csv")
df
