#!/usr/bin/env bash

set -e

ret=$(cat /proc/sys/kernel/randomize_va_space)
if [ $ret -ne 0 ]; then
    echo "ASLR is NOT disabled. Please disable ASLR."
    exit 1
fi

#echo "Generating random arrays"
./gen_arr.sh A
./gen_arr.sh B

echo "Building"
g++ -w -O2 -fno-strict-aliasing test_A.cc ../../src/common/quantile.cc ../../src/common/obl_primitives.cc -I../../ -I../../dmlc-core/include -I../../include -o test_A -std=c++11 -mavx2
g++ -w -O2 -fno-strict-aliasing test_B.cc ../../src/common/quantile.cc ../../src/common/obl_primitives.cc -I../../ -I../../dmlc-core/include -I../../include -o test_B -std=c++11 -mavx2

echo "Done"
