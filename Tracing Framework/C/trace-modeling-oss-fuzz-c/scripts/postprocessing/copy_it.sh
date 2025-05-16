#!/bin/bash
# Copy source code from docker images

REPOS_DIR="repos_build_real"
LOG_FILE="copy_it.log"
DATA_FILE="data/projects_c.txt"
rm -f $LOG_FILE

function copyIt() {
    project=$1
    echo "Copying files for $project..."
    id=$(docker create gcr.io/oss-fuzz/$project)
    docker cp $id:$(docker inspect --format='{{.Config.WorkingDir}}' $id) $REPOS_DIR/$project
    docker rm -v $id >> /dev/null
}

if [ ! -z "$1" ]
then
    copyIt $1
else
    while read p
    do
        copyIt $p >> $LOG_FILE
        echo $p
    done < $DATA_FILE | tqdm --total $(cat $DATA_FILE | wc -l)
fi
