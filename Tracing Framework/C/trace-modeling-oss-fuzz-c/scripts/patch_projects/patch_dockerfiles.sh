#!/bin/bash
# to apply to dockerfiles: bash scripts/modify_dockerfiles.sh | patch -p0
while read l
do
    fname="projects/$l/Dockerfile"
    sed 's@gcr.io/oss-fuzz-base/base-builder@gcr.io/oss-fuzz-base/base-builder:gdb@g' $fname | diff --unified=0 $fname - | sed "s@^+++ -@+++ $fname@g"
done < data/projects_c.txt
