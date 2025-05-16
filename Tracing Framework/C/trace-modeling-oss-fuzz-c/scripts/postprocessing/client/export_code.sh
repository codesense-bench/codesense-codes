# find /src -name '*.c' -o -name '*.h' -print -exec cp --parents \{\} /export \;
tar --ignore-failed-read -h -cf /export/src.tar /src || [[ $? -eq 1 ]]
