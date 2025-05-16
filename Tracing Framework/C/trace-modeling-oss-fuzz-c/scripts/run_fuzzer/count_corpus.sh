#!/bin/bash
while read p
do
    while read f
    do
        fp="build/corpus/$p/$f"
        if [ -d $fp ]
        then
            echo $p $f $(ls $fp 2> /dev/null | wc -l)
        fi
    done < <(python infra/helper.py get_fuzz_targets $p)
done < data/projects_c.txt
