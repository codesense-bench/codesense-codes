echo "$0 args: $@"
bash $(dirname $0)/trace_project_fuzzer_testcase_sing.sh $@
echo $@ $? >> $OUTCOME_FILE
