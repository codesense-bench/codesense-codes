#!/bin/bash
base_name="base-runner"
docker save 260a1e8a28c7 -o base-runner.tar
singularity build base-runner.sif docker-archive://base-runner.tar
