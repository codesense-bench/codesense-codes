#!/bin/bash

project="$1"
fuzzer="$2"
testcase_path="$3"
output_path="$4"

if [ ! -e "$testcase_path" ]
then
    echo "Testcase not found: $testcase_path" 2>&1
    exit 1
fi

mkdir -p $output_path

docker_name="tracer_$(echo $RANDOM | md5sum | head -c 8; echo;)"

#function cleanup() {
    #docker rm -f $docker_name
#}
#trap cleanup EXIT HUP INT TERM

tracer_args="--function-hit-limit $(cat configs/tracing/function_limit.dat) --function-dedup"

set -x
# timeout $(cat configs/tracing/timeout.dat) python infra/helper.py --build-dir build_trace reproduce $project $fuzzer $testcase_path --num_runs 1 --container-name $docker_name --tracer-args "$tracer_args" -o $output_path
# timeout $(cat configs/tracing/timeout.dat) docker run --rm --privileged --shm-size=2g --platform linux/amd64 -e HELPER=True --name tracer_925d65f6 --env 'TRACER_ARGS=--function-hit-limit 1000 --function-dedup' -v /home/XXX/code/trace-modeling-oss-fuzz-c/build_trace/out/krb5:/out -v /home/XXX/code/trace-modeling-oss-fuzz-c/build/corpus/krb5/Fuzz_profile:/testcase -v /home/XXX/code/trace-modeling-oss-fuzz-c/tools/trace-modeling/trace_collection_c_cpp/tracer:/tracer -v /home/XXX/code/trace-modeling-oss-fuzz-c/traces_all/krb5/Fuzz_profile/all:/tracer_output -t gcr.io/oss-fuzz-base/base-runner:gdb reproduce Fuzz_profile -runs=1 -timeout=0
APPTAINERENV_HELPER=True APPTAINERENV_TRACER_ARGS=--function-hit-limit 1000 --function-dedup
timeout $(cat configs/tracing/timeout.dat) singularity exec \
    --bind build_trace/out/$project:/out \
    --bind $testcase_path:/testcase \
    --bind $PWD/tools/trace-modeling/trace_collection_c_cpp/tracer:/tracer \
    --bind $output_path:/tracer_output \
    ../sifs/base-runner.sif reproduce $fuzzer -runs=1 -timeout=0
exitCode=$?

exit $exitCode
