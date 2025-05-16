#!/bin/bash

# kill background processes on exit https://stackoverflow.com/a/22644006
trap "exit" INT TERM
trap "kill 0" EXIT

PID=$$

# TIMEOUT="2s"
# function limitTime() {
#     sleep $TIMEOUT && kill "$PID"
# }
# (echo "Killing $PID after $TIMEOUT" && limitTime) & # timeout

directory="testfiles"
fileLimit="5"
function limitFiles() {
    while true
    do
        if [ $(ls $directory | wc -l) -ge "$fileLimit" ]
        then
            kill "$PID"
        fi
        sleep 1
    done
}
(echo "Killing $PID after $directory has $fileLimit files" && limitFiles) & # limit number of files

# inferior process
counter=1
while true
do
    echo $counter
    touch $directory/$counter
    sleep 1s
    counter=$(( counter + 1 ))
done
