#!/bin/bash

set -e

export TRACED_ROOT="trace_test"
mkdir -p $TRACED_ROOT

bash scripts/build_fuzzers/build_project_fuzzers.sh apache-httpd
bash scripts/run_fuzzer2/fuzz_one.sh apache-httpd fuzz_addr_parse 2>&1 | tee $TRACED_ROOT/fuzz.log
bash scripts/run_tracer2/wrap_one.sh apache-httpd fuzz_addr_parse
bash scripts/run_tracer2/trace_one.sh apache-httpd fuzz_addr_parse $TRACED_ROOT/corpus $TRACED_ROOT/traces 2>&1 | tee $TRACED_ROOT/trace.log
