#!/bin/bash
TRACED_ROOT="${TRACED_ROOT:-data}"
PROJECT="$1"
shift
exec python3 infra/helper.py --build-dir $TRACED_ROOT/build build_fuzzers $PROJECT --export-code $@
