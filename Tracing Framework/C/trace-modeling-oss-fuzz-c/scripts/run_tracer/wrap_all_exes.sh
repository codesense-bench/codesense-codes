#!/bin/bash
# for d in build_trace/out/*; do bash scripts/run_tracer/wrap_all_exes.sh $d; done 2>&1 | tee wrap_all.log
# find build_trace/ -type f -mmin -10 > wrap_all_files.log

project_dir="$1"
while read f
do
    bash $(dirname $0)/wrap_exe.sh $project_dir/$f
done < <(python infra/helper.py get_fuzz_targets $(basename $project_dir)) # <(find $project_dir -type f -name 'fuzz_*' -not -name '*_exe')
