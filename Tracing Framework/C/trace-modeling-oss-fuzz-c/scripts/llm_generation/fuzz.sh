function helper() {
    python infra/helper.py --build-dir build_llm $@
}

for p in libucl libdwarf # libsndfile
do
    for f in $(helper get_fuzz_targets $p | grep harness_)
    do
        echo "Running fuzzer $p $f..."
        mkdir -p corpus_llm4/$p/$f
        (sleep 60; docker rm -f fuzz_$f) &
        helper run_fuzzer $p --corpus-dir corpus_llm4/$p/$f --docker-name fuzz_$f $f \
            max_total_time=60 seed=0 print_coverage=1 ignore_crashes=1 jobs=10
    done
done
