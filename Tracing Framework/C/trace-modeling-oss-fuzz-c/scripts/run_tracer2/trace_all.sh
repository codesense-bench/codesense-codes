#!/bin/bash

set -u

# sample_mode="true"
sample_mode="false"

PROJECTS_FILE="data/projects_c.txt"
TRACED_ROOT="${TRACED_ROOT:-data}"
build_root="$TRACED_ROOT/build"
corpus_root="$TRACED_ROOT/corpus"
traces_root="$TRACED_ROOT/traces"

source $(dirname $0)/functions.sh

function doSample() {
    if [ "$sample_mode" = true ]; then
        head -n 1
    else
        cat
    fi
}

function getProjects() {
    cat $PROJECTS_FILE | doSample | sort
}

function getFuzzers() {
    project="$1"
    $helper_cmd get_fuzz_targets $1 | doSample | sort
}

# function getTestcases() {
#     project="$1"
#     fuzzer="$2"
#     ls "$corpus_root/$project/$fuzzer" | doSample | sort
# }

LOG_FILE="trace_all.log"
OUTCOME_FILE="trace_all_outcomes.log"

rm -f $OUTCOME_FILE

while read project
do
    while read fuzzer
    do
        corpus_dir="$corpus_root/$project/$fuzzer"
        
        # process all files in corpus
        output_path="$traces_root/$project/$fuzzer/all"
        mkdir -p $output_path

        runTracer
        echo $project $fuzzer $corpus_dir $output_path $? >> $OUTCOME_FILE
    done < <(getFuzzers $project)
done < <(getProjects) 2>&1 | tee $LOG_FILE
