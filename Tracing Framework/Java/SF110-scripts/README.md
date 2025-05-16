# SF110/EvoSuite

Links
- Benchmark source: https://www.evosuite.org/experimental-data/sf110/
- Docker image: https://hub.docker.com/repository/docker/benjijang/sf110

How to run the scripts:

```bash
# Unzip SF110-20130704-src.zip and SF110-20130704.zip to this directory, don't overwrite build.xmls
# Download new versions of junit, hamcrest, and evosuite to lib/
bash download_libs.sh

# Drop into shell inside Docker container
bash docker_run.sh

# Start JDK docker container with `bash run.sh`, then enter shell with `docker exec -it sf110 bash`
# Inside docker container now...
python3 format.py       # Format all the build.xml files (should already be formatted in this repo)
python3 fix.py          # Fix all the build.xml files by adding paths to the correct libraries (should already be applied to this repo)
python3 generate_run.py # Run EvoSuite on all programs/classes; should take a long time!
python3 print_results.py results*.jsonl # Print the results
```

To run the tracer (WIP), see:

```bash
python3 add_jdwp_options.py # Add the option "traced.wait" to all build.xml files
```

# Citation

If you use this software, please cite it as below.

```
@software{Steenhoek_SF110_support_scripts_2024,
author = {Steenhoek, Benjamin Jeremiah},
month = feb,
title = {{SF110 support scripts}},
url = {https://github.com/bstee615/SF110-scripts},
version = {1.0.0},
year = {2024}
}
```
