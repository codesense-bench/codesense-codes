# DEPRECATED: use patch_build_scripts.py

while read l
do
    f="projects/$l/build.sh"
    #  -DCMAKE_BUILD_TYPE=Debug
    if [ ! -f $f ]
    then
        continue
    elif grep -H -e './configure[^.]' -e './configure$' $f 2> /dev/null
    then
        continue
    elif grep -H -e 'cmake ' -e 'cmake$' $f 2> /dev/null
    then
        continue
    elif grep -H -e 'meson ' -e 'meson$' $f 2> /dev/null
    then
        continue
    elif grep -H -e 'make ' -e 'make$' $f 2> /dev/null
    then
        continue
    elif grep -Hw -E -e 'oss[-_]?fuzz.*\.sh' -e 'fuzz.*/build\.sh' -e 'build-fuzzers\.sh' -e 'oss-fuzz\.py' $f 2> /dev/null
    then
        continue
    elif grep -Hw -e '$CC $CFLAGS' -e '$CXX $CXXFLAGS' $f 2> /dev/null
    then
        continue
    else
        echo NO MATCH: $f
    fi
done < data/projects_c.txt  | grep -v 'build.sh:#'