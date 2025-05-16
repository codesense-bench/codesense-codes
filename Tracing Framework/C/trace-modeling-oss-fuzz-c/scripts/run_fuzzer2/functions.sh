#!/bin/bash

helper_cmd="python infra/helper.py --build-dir $build_root"

function runFuzzer() {
    timeout=10
    kill_delay=10

    corpus_dir="$corpus_root/$project/$fuzzer"
    mkdir -p "$corpus_dir"

    container_name="trace_${project}_${fuzzer}_$(basename $corpus_dir)"
    python $(dirname $(dirname $0))/kill_container.py "$container_name" "$(( $timeout + $kill_delay ))" &
    bgpid=$!

    $helper_cmd run_fuzzer --corpus-dir $corpus_dir --docker-name fuzz_${project}_${fuzzer} $project $fuzzer \
        max_total_time=$timeout seed=0 print_coverage=1 ignore_crashes=1 jobs=10

    exitCode=$?
    kill -INT $bgpid

    return $exitCode
}
