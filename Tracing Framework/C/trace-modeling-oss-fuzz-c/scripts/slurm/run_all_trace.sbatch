#!/bin/bash

# Copy/paste this job script into a text file and submit with the command:
#    sbatch thefilename

#SBATCH --time=2-00:00:00   # walltime limit (HH:MM:SS)
#SBATCH --nodes=1   # number of nodes
#SBATCH --ntasks-per-node=10   # 36 processor core(s) per node 
#SBATCH --job-name="tracemeister"
#SBATCH --mail-user=XXX@iastate.edu   # email address
#SBATCH --mail-type=BEGIN
#SBATCH --mail-type=END
#SBATCH --mail-type=FAIL
#SBATCH --output="trace-%j.out" # job standard output file (%j replaced by job id)
#SBATCH --error="trace-%j.out" # job standard error file (%j replaced by job id)

# LOAD MODULES, INSERT CODE, AND RUN YOUR PROGRAMS HERE
module load singularity

bash scripts/run_tracer/trace_all_parallel.sh $@

