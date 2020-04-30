#!/usr/bin/env bash

FILE="arr_$1.h"
echo "std::vector<int> V = {" > $FILE

for i in {1..999}
do
    echo -n $RANDOM"," >> $FILE
done
echo -n $RANDOM "};" >> $FILE
