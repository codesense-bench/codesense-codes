#!/bin/bash

set -u

TRACED_ROOT="${TRACED_ROOT:-data}"
build_root="$TRACED_ROOT/build"
source $(dirname $0)/functions.sh

function runWrapCommand() {
    project="$1"
    fuzzer="$2"
    wrapExe
}

runWrapCommand $@
