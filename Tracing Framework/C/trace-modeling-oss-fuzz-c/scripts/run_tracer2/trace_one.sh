#!/bin/bash

set -u

TRACED_ROOT="${TRACED_ROOT:-data}"
build_root="$TRACED_ROOT/build"
source $(dirname $0)/functions.sh

function runTracerCommand() {
    project="$1"
    fuzzer="$2"
    corpus_root="$3"
    output_path="$4"
    runTracer
}

runTracerCommand $@
