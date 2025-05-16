echo "gzipping build/corpus/*..."
for d in build/corpus/*.tar
do
    echo FILE: $d
    if [ ! -f $d.gz ]
    then
        gzip -k $d
    fi
    ls $d.gz
done

cd build/corpus_pronto

echo "gzipping build/corpus_pronto/*..."
for d in build/corpus/*.tar
do
    if [ ! -f $d.gz ]
    then
        gzip -k $d
    fi
    ls $d.gz
done
