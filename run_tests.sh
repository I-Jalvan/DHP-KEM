#!/usr/bin/env bash
# run_tests.sh  —  one-shot runner for all DHP-KEM tests.
#
# Usage:    ./run_tests.sh             # all tests
#           ./run_tests.sh fast        # skip the slower correctness sweep
#
set -e
cd "$(dirname "$0")"

echo "============================================================"
echo "DHP-KEM TEST SUITE"
echo "============================================================"

# 1. Generate the KAT file if it doesn't exist yet
if [ ! -f kat_vectors/dhp_kem_kat_v1.json ]; then
    echo "--> Generating KAT file (first run only)"
    python3 -m tests.test_kat --generate
fi

# 2. Run each test module in turn
modules=( tests.test_combiner tests.test_kat tests.test_negative tests.test_timing )
if [ "$1" != "fast" ]; then
    modules+=( tests.test_correctness )
fi

for m in "${modules[@]}"; do
    echo "------------------------------------------------------------"
    echo ">> $m"
    echo "------------------------------------------------------------"
    python3 -m "$m"
done

echo "============================================================"
echo "ALL TESTS PASSED"
echo "============================================================"
