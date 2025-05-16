#!/bin/bash

exe="$1"

if [ ! -f "$exe" ]
then
    echo "File not found: $exe" 1>&2
    exit 1
fi

if ( [ $(stat -c "%a" "$exe") == "750" ] || [ $(stat -c "%a" "$exe") == "755" ] ) && file "$exe" | grep "ELF 64-bit" &> /dev/null
then
    mv $exe ${exe}_exe

    cat > $exe <<EOF
#!/bin/bash
OUTPUT_DIR=/tracer_output eval /tracer/trace \${0}_exe \$@
EOF
    chmod +x $exe
else
    (
        echo "Not binary executable: $exe" $(stat -c "%a" "$exe") $(file "$exe")
    ) 1>&2
fi
