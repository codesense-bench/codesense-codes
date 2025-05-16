#!/bin/bash
project=$1
fuzzer=$2
timeout=$3
file_limit=$4
corpus_dir=$5
jobs=$6
STARTTIME="$(date +%s)"

ENDTIME="$(( $STARTTIME + $timeout ))"
NOW="$STARTTIME"
seed=123

# kill background processes on exit https://stackoverflow.com/a/22644006
# trap "exit" INT TERM
# trap "kill 0" EXIT

docker_name="$(echo $RANDOM | md5sum | head -c 8)"

should_continue=true
PID=$$
function limitFiles() {
    while true
    do
        if ps -p $PID > /dev/null
        then
            if [ $(ls $corpus_dir | wc -l) -ge "$file_limit" ]
            then
                echo "KILLING DUE TO FILE LIMIT: $PID ($project, $fuzzer) timeout=$timeout (from $NOW til $ENDTIME) file_limit=$file_limit (pid $PID) seed=$seed..."
                kill "$PID"
                docker rm -f "$docker_name" > /dev/null
                should_continue=false
                break
            fi
        else
            break
        fi
        sleep 1
    done
}
limitFiles & # limit number of files

mkdir -p $corpus_dir
while [ $NOW -lt $ENDTIME ] && [ "$should_continue" = "true" ]
do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]: Running fuzzer for ($project, $fuzzer) timeout=$timeout (from $NOW til $ENDTIME) file_limit=$file_limit (pid $PID) seed=$seed..."
    jobs_args=""
    if [ ! -z "$jobs" ]
    then
        jobs_args="jobs=$jobs workers=$jobs"
    fi
    exec python infra/helper.py run_fuzzer --corpus-dir $corpus_dir --docker-name $docker_name $project $fuzzer max_total_time=$timeout seed=$seed print_final_stats=1 $jobs_args
    timeout="$(( $ENDTIME - $NOW ))"
    NOW="$(date +%s)"
    seed="$(( $seed + 1 ))"
done
