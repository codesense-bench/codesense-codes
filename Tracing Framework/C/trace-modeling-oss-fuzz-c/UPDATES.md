## 2024-01-24: Fix repo code cache

```bash
git pull
# Container was updated with new script for export_code
(cd infra/base-images/base-builder; docker build -t gcr.io/oss-fuzz-base/base-builder:trace-modeling .)
# Build + wrap must be rerun for any projects which were run before. Fuzzing results are unaffected.
bash scripts/build_fuzzers/build_project_fuzzers.sh apache-httpd
bash scripts/run_tracer2/wrap_one.sh apache-httpd fuzz_addr_parse
bash scripts/run_tracer2/trace_one.sh apache-httpd fuzz_addr_parse $TRACED_ROOT/corpus $TRACED_ROOT/traces
```
