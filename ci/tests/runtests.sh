#!/bin/bash

passed=0
failed=0
total=0
for test in `find tests -name runtest.sh -type f | sort`
do
    testdir=$(dirname ${test})
    echo "RUNNING TEST: ${testdir}"
    echo "---------------------"
    if ${test}
    then
        passed=$((passed+1))
    else
        failed=$((failed+1))
    fi
    echo ""
    total=$((total+1))
done

echo "+====================================+"
printf "| Summary: %2d/%2d/%2d total/pass/fail  |\n" ${total} ${passed} ${failed}
echo "+====================================+"

exit ${failed}
