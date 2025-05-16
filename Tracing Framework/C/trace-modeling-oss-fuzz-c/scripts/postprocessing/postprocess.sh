#!/bin/bash

# SAMPLE="--sample"
# SINGLE_THREAD="--single_thread"

NPROC=10
LOGFILE=postprocess.log

INDIR="repaired_xmls/logs-xmls"
OUTFILE="postprocessed.jsonl"
python scripts/4_postprocess/2_main.py $INDIR $OUTFILE $SAMPLE $SINGLE_THREAD --nproc $NPROC 2>&1 | tee $LOGFILE

INFILE="$OUTFILE"
OUTFILE="${INFILE%.jsonl}_dedup.jsonl"
python scripts/4_postprocess/3_dedup_filter_examples.py $INFILE $OUTFILE 2>&1 | tee -a $LOGFILE

INFILE="$OUTFILE"
OUTFILE="${INFILE%.jsonl}_sort.jsonl"
python scripts/4_postprocess/4_sort_examples.py $INFILE $OUTFILE 2>&1 | tee -a $LOGFILE

python scripts/4_postprocess/5_stats2.py $OUTFILE 2>&1 | tee -a $LOGFILE

python scripts/4_postprocess/8_filter_variables.py $OUTFILE 2>&1 | tee -a $LOGFILE
