#!/bin/bash

helper_cmd="python infra/helper.py --build-dir $build_root"

function runTracer() {
    timeout=60 # how many seconds should tracing run
    function_hit_limit=10 # how many times should we trace a function before skipping it for the rest of the times we hit it
    kill_delay=300 # set extra-long kill delay to try to allow the tracer to exit cleanly

    corpus_dir="$corpus_root/$project/$fuzzer"
    mkdir -p "$corpus_dir"

    container_name="trace_${project}_${fuzzer}_$(basename $corpus_dir)"
    python $(dirname $(dirname $0))/kill_container.py "$container_name" "$(( $timeout + $kill_delay ))" &
    bgpid=$!

    $helper_cmd reproduce $project $fuzzer $corpus_dir --docker-name $container_name \
        --num_runs 1 --tracer-args "--entry-function LLVMFuzzerTestOneInput --function-hit-limit $function_hit_limit --deduplicate-function-hits --timeout $timeout" --output $output_path

    exitCode=$?
    kill -9 $bgpid

    return $exitCode
}

function wrapExe() {
    # Wrap executable
    exe="$build_root/out/$project/$fuzzer"

    if [ ! -f "$exe" ]
    then
        echo "File not found: $exe" 1>&2
        exit 1
    fi

    if ( [ $(stat -c "%a" "$exe") == "750" ] || [ $(stat -c "%a" "$exe") == "755" ] ) && file "$exe" | grep "ELF 64-bit" &> /dev/null
    then
        if [ ! -f "${exe}_exe" ]
        then
            mv $exe ${exe}_exe
        fi

    cat > $exe <<EOF
#!/bin/bash
OUTPUT_DIR=/tracer_output /tracer/trace \${0}_exe \$@
EOF
    chmod +x $exe
    else
        (
            echo "Not binary executable: $exe" $(stat -c "%a" "$exe") $(file "$exe")
        ) 1>&2
    fi

    # Export code
    (cd $build_root/out/$project; tar -xvf src.tar --exclude "${fuzzer}_exe")
}
