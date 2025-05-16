#!/bin/bash
# for d in build_trace/out/*; do bash scripts/run_tracer/wrap_all_exes.sh $d; done 2>&1 | tee wrap_all.log
# find build_trace/ -type f -mmin -10 > wrap_all_files.log

set -u

source $(dirname $0)/functions.sh

build_root="trace_test/build"
source $(dirname $0)/functions.sh

while read project
do
    while read fuzzer
    do
        wrapExe
    done < <(getFuzzers $project)
done < <(getProjects)
