#!/bin/bash


echo "Running RQ_3_loop.sh..."
./RQ_3_loop.sh


if [ $? -eq 0 ]; then
    echo "RQ_3_loop.sh completed successfully"

    echo "Running RQ_5_1.sh..."
    ./RQ_5_1.sh
    
    if [ $? -eq 0 ]; then
        echo "RQ_5_1.sh completed successfully"
    else
        echo "RQ_5_1.sh failed"
        exit 1
    fi
else
    echo "RQ_3_loop.sh failed"
    exit 1
fi

echo "Both scripts executed successfully"
exit 0