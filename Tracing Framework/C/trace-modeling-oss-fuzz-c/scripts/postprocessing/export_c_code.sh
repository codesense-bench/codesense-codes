date | tee export_c_code.log
for project in $(cat data/projects_c.txt)
do
    echo "exporting $project..."
    docker run --rm -it -v $PWD/c_code_export/$project:/export gcr.io/oss-fuzz/$project bash -c "tar --ignore-failed-read -cfh /export/src.tar /src"
done 2>&1 | tee -a export_c_code.log
date | tee -a export_c_code.log
