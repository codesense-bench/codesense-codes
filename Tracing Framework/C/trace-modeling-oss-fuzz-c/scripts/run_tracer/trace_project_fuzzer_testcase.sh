#!/bin/bash

project="$1"
fuzzer="$2"
testcase_path="$3"
output_path="$4"

# build_dir="build_trace"
build_dir="build"

if [ ! -e "$testcase_path" ]
then
    echo "Testcase not found: $testcase_path" 2>&1
    exit 1
fi

mkdir -p $output_path

docker_name="tracer_$(echo $RANDOM | md5sum | head -c 8; echo;)"

function cleanup() {
    docker rm -f $docker_name
}
trap cleanup EXIT HUP INT TERM

tracer_args="--function-hit-limit $(cat configs/tracing/function_limit.dat) --function-dedup"

set -x
timeout $(cat configs/tracing/timeout.dat) python infra/helper.py --build-dir $build_dir reproduce $project $fuzzer $testcase_path --num_runs 1 --container-name $docker_name --tracer-args "$tracer_args" -o $output_path
exitCode=$?

exit $exitCode
