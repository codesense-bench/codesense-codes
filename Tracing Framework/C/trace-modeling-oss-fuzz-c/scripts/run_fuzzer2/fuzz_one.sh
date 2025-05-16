#!/bin/bash

set -u

TRACED_ROOT="${TRACED_ROOT:-data}"
build_root="$TRACED_ROOT/build"
corpus_root="$TRACED_ROOT/corpus"
source $(dirname $0)/functions.sh

function runFuzzerCommand() {
    project="$1"
    fuzzer="$2"
    runFuzzer
}

runFuzzerCommand $@
