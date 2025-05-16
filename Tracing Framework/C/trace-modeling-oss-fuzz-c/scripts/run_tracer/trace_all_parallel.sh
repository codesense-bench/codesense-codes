#!/bin/bash

# sample_mode="true"
sample_mode="false"

PROJECTS_FILE="data/projects_c_trace.txt"
corpus_root="build/corpus"
traces_root="traces_all"

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
    python infra/helper.py get_fuzz_targets $1 | doSample | sort
}

function getTestcases() {
    project="$1"
    fuzzer="$2"
    ls "$corpus_root/$project/$fuzzer" | doSample | sort
}

LOG_FILE="trace_all_parallel.log"
OUTCOME_FILE="trace_all_parallel_outcomes.log"
export OUTCOME_FILE

rm -f $OUTCOME_FILE
echo "Printing output to $LOG_FILE, outcomes to $OUTCOME_FILE."

(
    while read project
    do
        while read fuzzer
        do
            corpus_dir="$corpus_root/$project/$fuzzer"

            # process all files in corpus
            output_path="$traces_root/$project/$fuzzer/all"
            if [ -d "$output_path" ]
            then
                echo "skipping project $p fuzzer $f - $output_path exists" 1>&2
                continue
            fi
            echo $project $fuzzer $corpus_dir $output_path
        done < <(getFuzzers $project)
    done < <(getProjects) | parallel --group --jobs 10 --joblog "$LOG_FILE.job" --colsep ' ' bash $(dirname $0)/trace_one_parallel.sh {}
) &> $LOG_FILE
