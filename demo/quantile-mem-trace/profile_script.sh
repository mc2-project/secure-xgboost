#!/usr/bin/env bash
echo "start test"
$PIN_ROOT/pin -t $PIN_ROOT/source/tools/ManualExamples/obj-intel64/pinatrace.so -- ./test_A;
mv pinatrace.out test_A.trace;

$PIN_ROOT/pin -t $PIN_ROOT/source/tools/ManualExamples/obj-intel64/pinatrace.so -- ./test_B;
mv pinatrace.out test_B.trace;
