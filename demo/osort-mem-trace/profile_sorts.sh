#!/usr/bin/env bash

$PIN_ROOT/pin -t $PIN_ROOT/source/tools/ManualExamples/obj-intel64/pinatrace.so -- ./sort_A S;
mv pinatrace.out std_sort_A.trace;

$PIN_ROOT/pin -t $PIN_ROOT/source/tools/ManualExamples/obj-intel64/pinatrace.so -- ./sort_B S;
mv pinatrace.out std_sort_B.trace;

$PIN_ROOT/pin -t $PIN_ROOT/source/tools/ManualExamples/obj-intel64/pinatrace.so -- ./sort_A O;
mv pinatrace.out o_sort_A.trace;

$PIN_ROOT/pin -t $PIN_ROOT/source/tools/ManualExamples/obj-intel64/pinatrace.so -- ./sort_B O;
mv pinatrace.out o_sort_B.trace;
