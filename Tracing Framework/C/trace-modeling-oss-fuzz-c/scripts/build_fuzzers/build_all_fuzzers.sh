#!/bin/bash
DATA_FILE="data/projects_c.txt"
function getData() {
    cat $DATA_FILE
    # head -n1 $DATA_FILE
}
project="$1"
if [ ! -z "$project" ]
then
    LOG_FILE="build_all_fuzzers_${project}.log"
    OUTCOME_FILE="build_all_fuzzers_outcomes.log"
else
    LOG_FILE="build_all_fuzzers.log"
    OUTCOME_FILE="build_all_fuzzers_outcomes.log"
fi
while read p
do
    if [ ! -z "$project" ] && [ $p != "$project" ]
    then
        continue
    fi
    set -x
    bash $(dirname $0)/build_project_fuzzers.sh $p --clean
    echo $p $? >> $OUTCOME_FILE
    set +x
done < <(getData) 2>&1 | tee $LOG_FILE
