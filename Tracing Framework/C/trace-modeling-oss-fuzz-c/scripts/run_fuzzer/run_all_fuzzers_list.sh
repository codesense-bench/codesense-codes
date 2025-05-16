#!/bin/bash
DATA_FILE="$1"
function getData() {
    cat $DATA_FILE
    # head -n1 $DATA_FILE
}
project=""
fuzzer=""
# timeout="3600"
# nprocs="8"
if [ ! -z "$project" ]
then
    LOG_FILE="run_all_fuzzers_${project}_${fuzzer}.log"
    OUTCOME_FILE="run_all_fuzzers_${project}_${fuzzer}_outcomes.log"
else
    LOG_FILE="run_all_fuzzers_$(echo $DATA_FILE | sed 's@/@_@g').log"
    OUTCOME_FILE="run_all_fuzzers_outcomes_$(echo $DATA_FILE | sed 's@/@_@g').log"
fi
while read pf
do
    p="$(echo $pf | cut -d' ' -f1)"
    f="$(echo $pf | cut -d' ' -f2)"
    if [ ! -z "$project" ] && [ $p != "$project" ]
    then
        continue
    fi
        if [ ! -z "$fuzzer" ] && [ $f != "$fuzzer" ]
        then
            continue
        fi
        timeout=$(cat configs/fuzzing/timeout.dat)
        nprocs=$(cat configs/fuzzing/nprocs.dat)
        file_limit=$(cat configs/fuzzing/file_limit.dat)
        corpus_dir="build/corpus/$p/$f"
        if [ -d "$corpus_dir" ]
        then
            echo "skipping project $p fuzzer $f - $corpus_dir exists"
            continue
        fi
        mkdir -p "$corpus_dir"
        echo running project $p fuzzer $f timeout $timeout file-limit $file_limit procs $nprocs and saving corpus to $corpus_dir...
        set -x
        bash $(dirname $0)/run_project_fuzzer_singularity.sh $p $f $timeout $file_limit $corpus_dir $nprocs
        set +x
        echo $(date) $p $f $? >> $OUTCOME_FILE
done < <(getData) 2>&1 | tee $LOG_FILE
